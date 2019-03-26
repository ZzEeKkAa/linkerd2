package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/golang/protobuf/jsonpb"
	pb "github.com/linkerd/linkerd2/controller/gen/config"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type (
	upgradeOptions struct{ *installOptions }
)

func newUpgradeOptionsWithDefaults() *upgradeOptions {
	return &upgradeOptions{newInstallOptionsWithDefaults()}
}

func newCmdUpgrade() *cobra.Command {
	options := newUpgradeOptionsWithDefaults()

	cmd := &cobra.Command{
		Use:   "upgrade [flags]",
		Short: "Output Kubernetes configs to upgrade an existing Linkerd control plane",
		Long:  "Output Kubernetes configs to upgrade an existing Linkerd control plane.",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := newKubernetes()
			if err != nil {
				return err
			}

			values, configs, err := options.buildFromCluster(k)
			if err != nil {
				return err
			}

			return values.render(os.Stdout, configs)
		},
	}

	options.configure(cmd)
	return cmd
}

func newKubernetes() (*kubernetes.Clientset, error) {
	api, err := k8s.NewAPI(kubeconfigPath, kubeContext)
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(api.Config)
}

// fetchInstallValuesFromCluster checks the kubernetes API to fetch an existing
// linkerd configuration.
//
// This bypasses the public API so that we can access secrets and validate permissions.
func (options *upgradeOptions) buildFromCluster(k *kubernetes.Clientset) (*installValues, *pb.All, error) {
	if options.ignoreCluster {
		return nil, nil, errors.New("--ignore-cluster cannot be used with upgrade")
	}

	controllerReplicas := uint(1)
	identityReplicas := uint(1)
	selector := fmt.Sprintf("%s in (controller, identity)", k8s.ControllerComponentLabel)
	deploys, err := k.ExtensionsV1beta1().Deployments(controlPlaneNamespace).
		List(metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, nil, err
	}
	for _, deploy := range deploys.Items {
		if deploy.Spec.Replicas == nil {
			continue
		}
		r := uint(*deploy.Spec.Replicas)

		switch deploy.GetLabels()[k8s.ControllerComponentLabel] {
		case "controller":
			controllerReplicas = r
		case "identity":
			identityReplicas = r
		}
	}

	// Fetch the existing cluster configs or exit.
	configs := &pb.All{Global: &pb.Global{}, Proxy: &pb.Proxy{}}
	configMap, err := k.CoreV1().ConfigMaps(controlPlaneNamespace).
		Get(k8s.ConfigConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	uj := jsonpb.Unmarshaler{}
	if err := uj.Unmarshal(strings.NewReader(configMap.Data["global"]), configs.Global); err != nil {
		return nil, nil, err
	}
	if err := uj.Unmarshal(strings.NewReader(configMap.Data["proxy"]), configs.Proxy); err != nil {
		return nil, nil, err
	}

	// Override the configs from the command-line flags.
	options.overrideConfigs(configs)
	j := jsonpb.Marshaler{EmitDefaults: true}
	globalJSON, err := j.MarshalToString(configs.GetGlobal())
	if err != nil {
		return nil, nil, err
	}
	proxyJSON, err := j.MarshalToString(configs.GetProxy())
	if err != nil {
		return nil, nil, err
	}

	values := &installValues{
		// Container images:
		ControllerImage: fmt.Sprintf("%s/controller:%s", options.dockerRegistry, configs.GetGlobal().GetVersion()),
		WebImage:        fmt.Sprintf("%s/web:%s", options.dockerRegistry, configs.GetGlobal().GetVersion()),
		GrafanaImage:    fmt.Sprintf("%s/grafana:%s", options.dockerRegistry, configs.GetGlobal().GetVersion()),
		PrometheusImage: prometheusImage,
		ImagePullPolicy: configs.Proxy.ProxyImage.PullPolicy,

		// Kubernetes labels/annotations/resourcse:
		CreatedByAnnotation:      k8s.CreatedByAnnotation,
		CliVersion:               k8s.CreatedByAnnotationValue(),
		ControllerComponentLabel: k8s.ControllerComponentLabel,
		ProxyContainerName:       k8s.ProxyContainerName,
		ProxyInjectAnnotation:    k8s.ProxyInjectAnnotation,
		ProxyInjectDisabled:      k8s.ProxyInjectDisabled,

		// Controller configuration:
		Namespace:              controlPlaneNamespace,
		UUID:                   configs.GetGlobal().GetInstallationUuid(),
		ControllerLogLevel:     options.controllerLogLevel,
		PrometheusLogLevel:     toPromLogLevel(options.controllerLogLevel),
		ControllerReplicas:     controllerReplicas,
		ControllerUID:          options.controllerUID,
		EnableHA:               options.highAvailability,
		EnableH2Upgrade:        !options.disableH2Upgrade,
		NoInitContainer:        configs.GetGlobal().GetCniEnabled(),
		ProxyAutoInjectEnabled: configs.GetGlobal().GetAutoinjectContext() != nil,

		GlobalConfig: globalJSON,
		ProxyConfig:  proxyJSON,
	}

	idctx := configs.GetGlobal().GetIdentityContext()
	if idctx == nil {
		// If we're upgrading from a version without identity, generate a new one.
		i, err := newInstallIdentityOptionsWithDefaults().genValues()
		if err != nil {
			return nil, nil, err
		}

		values.Identity = i
		return values, configs, nil
	}

	trustPEM := idctx.GetTrustAnchorsPem()
	roots, err := tls.DecodePEMCertPool(trustPEM)
	if err != nil {
		return nil, nil, err
	}

	secret, err := k.CoreV1().Secrets(controlPlaneNamespace).
		Get(k8s.IdentityIssuerSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	keyPEM := string(secret.Data["key.pem"])
	key, err := tls.DecodePEMKey(keyPEM)
	if err != nil {
		return nil, nil, err
	}

	crtPEM := string(secret.Data["crt.pem"])
	crt, err := tls.DecodePEMCrt(crtPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid issuer certificate: %s", err)
	}

	cred := tls.Cred{PrivateKey: key, Crt: *crt}
	if err := cred.Verify(roots, ""); err != nil {
		return nil, nil, fmt.Errorf("invalid issuer credentials: %s", err)
	}

	values.Identity = &installIdentityValues{
		Replicas:        identityReplicas,
		TrustDomain:     idctx.GetTrustDomain(),
		TrustAnchorsPEM: trustPEM,
		Issuer: &issuerValues{
			ClockSkewAllowance:  idctx.GetClockSkewAllowance().String(),
			IssuanceLifetime:    idctx.GetIssuanceLifetime().String(),
			KeyPEM:              keyPEM,
			CrtPEM:              crtPEM,
			CrtExpiry:           crt.Certificate.NotAfter,
			CrtExpiryAnnotation: k8s.IdentityIssuerExpiryAnnotation,
		},
	}

	return values, configs, nil
}
