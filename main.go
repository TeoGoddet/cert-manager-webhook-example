package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"context"

	k8s_ext_apiv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	k8s_core_apiv1 "k8s.io/api/core/v1"
	k8s_meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	
    lego "github.com/go-acme/lego/v4/providers/dns"
    lego_interface "github.com/go-acme/lego/v4/challenge"

	logf "github.com/jetstack/cert-manager/pkg/logs"

)

var GroupName = os.Getenv("GROUP_NAME")
var SolverName = os.Getenv("SOLVER_NAME")


func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}
	
	if SolverName == "" {
		SolverName = "lego"
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	Provider           string `json:"provider"`
	EnvVars                []k8s_core_apiv1.EnvVar `json:"env,omitempty"`
	//EnvFrom            []k8s_core_apiv1.EnvSource `json:"envFrom,omitempty"`
}


// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return SecretSolverName
}

// prepare everything for the Present and Cleanup action (config, load lego provider, load env vars)
func (c *customDNSProviderSolver) prepare(ch *v1alpha1.ChallengeRequest) (lego_interface.Provider, customDNSProviderConfig, error) {
    cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, cfg, err
	}

	c.resolveEnvVars(cfg.EnvVars, ch.ResourceNamespace)
	c.loadEnvVars(cfg.EnvVars)

	fmt.Printf("REQUETE : %+v\n", ch)

	// remove the _acme-challenge from the FQDN so that lego does not add it twice
	ch.ResolvedFQDN = strings.SplitN(ch.ResolvedFQDN, ".", 2)[1]

	provider, err := lego.NewDNSChallengeProviderByName(cfg.Provider)
	if err != nil {
	    logf.Log.Error(err, "An error occured when loading lego DNS provider [provider] :  err", "provider", cfg.Provider)
		return provider, cfg, err
	}

	return provider, cfg, nil
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {

	provider, cfg, err := c.prepare(ch);
	if err != nil {
		return err
	}	

	logf.Log.Info("Delegate present action to provider for domain (resolvedDomain)\n with key key_", "provider", cfg.Provider, "domain", ch.DNSName, "resolvedDomain", ch.ResolvedFQDN, "key_", ch.PreHashKey)
	
	fmt.Printf("just before  _________: %v\n", ch.ResolvedFQDN)

	err = provider.Present(ch.ResolvedFQDN, ch.Token, ch.PreHashKey)

	c.unloadEnvVars(cfg.EnvVars)

	if err != nil {
		logf.Log.Error(err, "An error occured while presenting the record :  err")
		return err;
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
		provider, cfg, err := c.prepare(ch);
	if err != nil {
		return err
	}
	
	logf.Log.Info("Delegate cleanup action to provider for domain (resolvedDomain)\n with key key", "provider", cfg.Provider, "domain", ch.DNSName, "resolvedDomain", ch.ResolvedFQDN, "key", ch.PreHashKey)
	
	err = provider.CleanUp(ch.ResolvedFQDN, ch.Token, ch.PreHashKey)
	c.unloadEnvVars(cfg.EnvVars)

	if err != nil {
		logf.Log.Error(err, "An error occured while cleaning up the record :  err")
		return err
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

    c.client = cl

	logf.Log.Info("Initialized kubernetes client.")

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *k8s_ext_apiv1beta1.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}


func (c *customDNSProviderSolver) loadEnvVars(envs []k8s_core_apiv1.EnvVar) {
	for _, envVar := range envs{
		os.Setenv(envVar.Name, envVar.Value);
	}
}

func (c *customDNSProviderSolver) unloadEnvVars(envs []k8s_core_apiv1.EnvVar) {
	for _, envVar := range envs{
		os.Unsetenv(envVar.Name);
	}
}

// Insipred from : 
// https://github.com/kubernetes/kubernetes/blob/5310e4f30e212a3d58b37fd07633c3b249627b53/pkg/kubelet/kubelet_pods.go#L681
// See for EnvFrom support https://github.com/kubernetes/kubernetes/blob/5310e4f30e212a3d58b37fd07633c3b249627b53/pkg/kubelet/kubelet_pods.go#L604
// See also ovh webhook dns provider
func (c *customDNSProviderSolver) resolveEnvVars(envs []k8s_core_apiv1.EnvVar, namespace string) {
	for index, envVar := range envs{
		err := error(nil)
		runtimeVal := envVar.Value
		if runtimeVal != "" {
			// Step 1a: expand variable references
			//	runtimeVal = expansion.Expand(runtimeVal, mappingFunc) // 
			//TODO may need to support this
		} else if envVar.ValueFrom != nil {
			// Step 1b: resolve alternate env var sources
			switch {
			case envVar.ValueFrom.ConfigMapKeyRef != nil:
				runtimeVal, err = c.configMap(envVar.ValueFrom.ConfigMapKeyRef, namespace)
				break;
			case envVar.ValueFrom.SecretKeyRef != nil:
				runtimeVal, err = c.secret(envVar.ValueFrom.SecretKeyRef, namespace)
				break;
			default:
				err = fmt.Errorf("%+v as envRef is not implemented yet ! (only configMapRef and SecretKeyRef are implemented)", envVar.ValueFrom)
			}
		}
		if(err != nil){
		 logf.Log.Error(err, "An error occured when while handling env var env :  err\n Continuing with \"\" as value !", "env", envVar.Name)
		}
		envs[index].Value = runtimeVal
	}

}

func (c *customDNSProviderSolver) secret(ref *k8s_core_apiv1.SecretKeySelector, namespace string) (string, error) {
	if ref.Name == "" {
		return "", fmt.Errorf("Secret name not present in secretKeyRef (%+v)", ref)
	}

	secret, err := c.client.CoreV1().Secrets(namespace).Get(context.TODO(), ref.Name, k8s_meta_v1.GetOptions{})
	if err != nil {
		return "", err
	}

	bytes, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key not found %q in secret '%s/%s'", ref.Key, namespace, ref.Name)
	}
	return string(bytes), nil
}

func (c *customDNSProviderSolver) configMap(ref *k8s_core_apiv1.ConfigMapKeySelector, namespace string) (string, error) {
	if ref.Name == "" {
		return "", fmt.Errorf("configMap name not present in configMapKeyRef (%+v)", ref)
	}

	configmap, err := c.client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), ref.Name, k8s_meta_v1.GetOptions{})
	if err != nil {
		return "", err
	}

	bytes, ok := configmap.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key not found %q in configMap '%s/%s'", ref.Key, namespace, ref.Name)
	}
	return string(bytes), nil
}

