package router

import (
	"errors"
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"

	ocmd "github.com/openshift/origin/pkg/cmd/cli/cmd"
	"github.com/openshift/origin/pkg/cmd/templates"
	"github.com/openshift/origin/pkg/cmd/util"
	"github.com/openshift/origin/pkg/cmd/util/clientcmd"
	projectinternalclientset "github.com/openshift/origin/pkg/project/generated/internalclientset"
	routeapi "github.com/openshift/origin/pkg/route/apis/route"
	routeinternalclientset "github.com/openshift/origin/pkg/route/generated/internalclientset"
	"github.com/openshift/origin/pkg/router/controller"
	f5plugin "github.com/openshift/origin/pkg/router/f5"
)

var (
	f5Long = templates.LongDesc(`
		Start an F5 route synchronizer

		This command launches a process that will synchronize an F5 to the route configuration of your master.

		You may restrict the set of routes exposed to a single project (with --namespace), projects your client has
		access to with a set of labels (--project-labels), namespaces matching a label (--namespace-labels), or all
		namespaces (no argument). You can limit the routes to those matching a --labels or --fields selector. Note
		that you must have a cluster-wide administrative role to view all namespaces.`)
)

// F5RouterOptions represent the complete structure needed to start an F5 router
// sync process.
type F5RouterOptions struct {
	Config *clientcmd.Config

	F5Router
	RouterSelection
}

// F5Router is the config necessary to start an F5 router plugin.
type F5Router struct {
	RouterName string

	// Host specifies the hostname or IP address of the F5 BIG-IP host.
	Host string

	// To verify against alternate CA certificates or a self-signed certificate with the CA flag.
	CaBundle string

	// To verify certificates with a hostname that does not match what is in the host field (above), put the certificate hostname here.
	AltHostname string

	// Username specifies the username with which the plugin should authenticate
	// with the F5 BIG-IP host.
	Username string

	// Password specifies the password with which the plugin should authenticate
	// with the F5 BIG-IP host.
	Password string

	// Enable VXLAN FDB programming.
	EnableVxlan bool

	// PartitionPath specifies the path to the F5 partition. This is
	// normally used to create access control boundaries for users
	// and applications.
	PartitionPath string

	// HttpVserver specifies the name of the vserver object in F5 BIG-IP that the
	// plugin will configure for HTTP connections.
	HttpVserver string

	// HttpsVserver specifies the name of the vserver object in F5 BIG-IP that the
	// plugin will configure for HTTPS connections.
	HttpsVserver string
}

// Bind binds F5Router arguments to flags
func (o *F5Router) Bind(flag *pflag.FlagSet) {
	flag.StringVar(&o.RouterName, "name", util.Env("ROUTER_SERVICE_NAME", "public"), "The name the router will identify itself with in the route status")
	flag.StringVar(&o.Host, "f5-host", util.Env("ROUTER_EXTERNAL_HOST_HOSTNAME", ""), "The host of F5 BIG-IP's management interface")
	flag.StringVar(&o.CaBundle, "f5-cabundle", util.Env("ROUTER_EXTERNAL_CA_BUNDLE", ""), "The CA bundle for validating server certificate")
	flag.StringVar(&o.AltHostname, "f5-althostname", util.Env("ROUTER_EXTERNAL_ALT_HOSTNAME", ""), "The hostname for validating server certificate")
	flag.StringVar(&o.Username, "f5-username", util.Env("ROUTER_EXTERNAL_HOST_USERNAME", ""), "The username for F5 BIG-IP's management utility")
	flag.StringVar(&o.Password, "f5-password", util.Env("ROUTER_EXTERNAL_HOST_PASSWORD", ""), "The password for F5 BIG-IP's management utility")
	flag.StringVar(&o.PartitionPath, "f5-partition-path", util.Env("ROUTER_EXTERNAL_HOST_PARTITION_PATH", f5plugin.F5DefaultPartitionPath), "The F5 BIG-IP partition path to use")
	flag.BoolVar(&o.EnableVxlan, "f5-enable-vxlan", util.Env("ROUTER_EXTERNAL_ENABLE_VXLAN", "") == "true", "Enable VXLAN FDB programming")
	flag.StringVar(&o.HttpVserver, "f5-http-vserver", util.Env("ROUTER_EXTERNAL_HOST_HTTP_VSERVER", "ose-vserver"), "The F5 BIG-IP virtual server for HTTP connections")
	flag.StringVar(&o.HttpsVserver, "f5-https-vserver", util.Env("ROUTER_EXTERNAL_HOST_HTTPS_VSERVER", "https-ose-vserver"), "The F5 BIG-IP virtual server for HTTPS connections")
}

// Validate verifies the required F5 flags are present
func (o *F5Router) Validate() error {
	if o.Host == "" {
		return errors.New("F5 host must be specified")
	}

	if o.Username == "" {
		return errors.New("F5 username must be specified")
	}

	if o.Password == "" {
		return errors.New("F5 password must be specified")
	}

	if len(o.HttpVserver) == 0 && len(o.HttpsVserver) == 0 {
		return errors.New("F5 HTTP and HTTPS vservers cannot both be blank")
	}

	return nil
}

// NewCommandF5Router provides CLI handler for the F5 router sync plugin.
func NewCommandF5Router(name string) *cobra.Command {
	options := &F5RouterOptions{
		Config: clientcmd.NewConfig(),
	}
	options.Config.FromFile = true

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("%s%s", name, clientcmd.ConfigSyntax),
		Short: "Start an F5 route synchronizer",
		Long:  f5Long,
		Run: func(c *cobra.Command, args []string) {
			options.RouterSelection.Namespace = cmdutil.GetFlagString(c, "namespace")
			cmdutil.CheckErr(options.Complete())
			cmdutil.CheckErr(options.Validate())
			cmdutil.CheckErr(options.Run())
		},
	}

	cmd.AddCommand(ocmd.NewCmdVersion(name, nil, os.Stdout, ocmd.VersionOptions{}))

	flag := cmd.Flags()
	options.Config.Bind(flag)
	options.F5Router.Bind(flag)
	options.RouterSelection.Bind(flag)

	return cmd
}

func (o *F5RouterOptions) Complete() error {
	if len(o.PartitionPath) == 0 {
		o.PartitionPath = f5plugin.F5DefaultPartitionPath
		glog.Warningf("Partition path was empty, using default: %q",
			f5plugin.F5DefaultPartitionPath)
	}

	return o.RouterSelection.Complete()
}

func (o *F5RouterOptions) Validate() error {
	return o.F5Router.Validate()
}

// F5RouteAdmitterFunc returns a func that checks if a route is a
// wildcard route and currently denies it.
func (o *F5RouterOptions) F5RouteAdmitterFunc() controller.RouteAdmissionFunc {
	return func(route *routeapi.Route) error {
		if err := o.AdmissionCheck(route); err != nil {
			return err
		}

		switch route.Spec.WildcardPolicy {
		case routeapi.WildcardPolicyNone:
			return nil

		case routeapi.WildcardPolicySubdomain:
			// TODO: F5 wildcard route support.
			return fmt.Errorf("Wildcard routes are currently not supported by the F5 router")
		}

		return fmt.Errorf("unknown wildcard policy %v", route.Spec.WildcardPolicy)
	}
}

// Run launches an F5 route sync process using the provided options. It never exits.
func (o *F5RouterOptions) Run() error {
	cfg := f5plugin.F5PluginConfig{
		Host:            o.Host,
		CaBundle:        o.CaBundle,
		AltHostname:     o.AltHostname,
		Username:        o.Username,
		Password:        o.Password,
		PartitionPath:   o.PartitionPath,
		EnableVxlan:     o.EnableVxlan,
		HttpVserver:     o.HttpVserver,
		HttpsVserver:    o.HttpsVserver,
	}
	f5Plugin, err := f5plugin.NewF5Plugin(cfg)
	if err != nil {
		return err
	}

	_, kc, err := o.Config.Clients()
	if err != nil {
		return err
	}
	routeclient, err := routeinternalclientset.NewForConfig(o.Config.OpenShiftConfig())
	if err != nil {
		return err
	}
	projectclient, err := projectinternalclientset.NewForConfig(o.Config.OpenShiftConfig())
	if err != nil {
		return err
	}

	statusPlugin := controller.NewStatusAdmitter(f5Plugin, routeclient, o.RouterName, "")
	uniqueHostPlugin := controller.NewUniqueHost(statusPlugin, o.RouteSelectionFunc(), o.RouterSelection.DisableNamespaceOwnershipCheck, statusPlugin)
	plugin := controller.NewHostAdmitter(uniqueHostPlugin, o.F5RouteAdmitterFunc(), false, o.RouterSelection.DisableNamespaceOwnershipCheck, statusPlugin)

	factory := o.RouterSelection.NewFactory(routeclient, projectclient.Projects(), kc)
	watchNodes := o.EnableVxlan
	controller := factory.Create(plugin, watchNodes, o.EnableIngress)
	controller.Run()

	select {}
}
