package f5

import (
	"fmt"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	kapi "k8s.io/kubernetes/pkg/api"

	routeapi "github.com/openshift/origin/pkg/route/apis/route"
	"github.com/openshift/origin/pkg/router/controller"
	"github.com/openshift/origin/pkg/util/netutils"
)

// F5Plugin holds state for the f5 plugin.
type F5Plugin struct {
	// F5Client is the object that represents the F5 BIG-IP host, holds state,
	// and provides an interface to manipulate F5 BIG-IP.
	F5Client *f5LTM

	// VtepMap is a map of node ids and their ip addresses
	// helps to sync events at router start vs node status update events
	VtepMap map[types.UID]string
}

// F5PluginConfig holds configuration for the f5 plugin.
type F5PluginConfig struct {
	// Host specifies the hostname or IP address of the F5 BIG-IP host.
	Host string

	// To verify against alternate CA certificates or a self-signed certificate with the CA flag.
	CaBundle string

	// To verify certificates with a hostname that does not match what is in the host field (above), put the certificate hostname here.
	AltHostname string

	// Username specifies the username with the plugin should authenticate
	// with the F5 BIG-IP host.
	Username string

	// Password specifies the password with which the plugin should
	// authenticate with F5 BIG-IP.
	Password string

	// PartitionPath specifies the F5 partition path to use. This is used
	// to create an access control boundary for users and applications.
	PartitionPath string

	// Enable VXLAN FDB programming.
	EnableVxlan bool

	// HttpVserver specifies the name of the vserver object in F5 BIG-IP that the
	// plugin will configure for HTTP connections.
	HttpVserver string

	// HttpsVserver specifies the name of the vserver object in F5 BIG-IP that the
	// plugin will configure for HTTPS connections.
	HttpsVserver string
}

// NewF5Plugin makes a new f5 router plugin.
func NewF5Plugin(cfg F5PluginConfig) (*F5Plugin, error) {
	f5LTMCfg := f5LTMCfg{
		host:            cfg.Host,
		cabundle:        cfg.CaBundle,
		althostname:     cfg.AltHostname,
		username:        cfg.Username,
		password:        cfg.Password,
		partitionPath:   cfg.PartitionPath,
		enableVxlan:     cfg.EnableVxlan,
		httpVserver:     cfg.HttpVserver,
		httpsVserver:    cfg.HttpsVserver,
	}
	f5, err := newF5LTM(f5LTMCfg)
	if err != nil {
		return nil, err
	}
	return &F5Plugin{f5, map[types.UID]string{}}, f5.Initialize()
}

// ensurePoolExists checks whether the named pool already exists in F5 BIG-IP
// and creates it if it does not.
func (p *F5Plugin) ensurePoolExists(poolname string) error {
	poolExists, err := p.F5Client.PoolExists(poolname)
	if err != nil {
		glog.V(4).Infof("F5Client.PoolExists failed: %v", err)
		return err
	}

	if ! poolExists {
		err = p.F5Client.CreatePool(poolname)
		if err != nil {
			glog.V(4).Infof("Error creating pool %s: %v", poolname, err)
			return err
		}
	}

	return nil
}

// updatePool update the named pool (which must already exist in F5 BIG-IP) with
// the given endpoints.
func (p *F5Plugin) updatePool(poolname string, endpoints *kapi.Endpoints) error {
	// Check if the pool exists.
	poolExists, err := p.F5Client.PoolExists(poolname)
	if err != nil {
		glog.V(4).Infof("F5Client.PoolExists failed: %v", err)
		return err
	}

	// Initialize needToDelete.
	needToDelete := map[string]bool{}

	// Populate needToDelete.
	if poolExists {
		members, err := p.F5Client.GetPoolMembers(poolname)
		if err != nil {
			glog.V(4).Infof("F5Client.GetPoolMembers failed: %v", err)
			return err
		}

		// We need to keep track of which endpoints already existed in F5 in order
		// to delete any that no longer exist in the updated set of endpoints.
		//
		// It would be really nifty if F5 would just let us PUT the new list of
		// endpoints to the pool members resource, bu-u-ut... it doesn't.   We can
		// only manipulate the pool by POSTing and DELETEing individual pool members,
		// so what we do is first POST things that should be in the pool but are not
		// and then DELETE things that are in the pool but should not be.
		//
		// We use needToDelete to keep track of pool members.  First we assume that
		// each pool member needs to be deleted (needToDelete[member] = true).  Then
		// we iterate over the given endpoints and update needToDelete for each pool
		// member that corresponds to one of those endpoints (needToDelete[dest]
		// = false).  Finally we iterate over needToDelete and delete anything that is
		// still marked for deletion (needToDelete[member] is true).
		//
		// Note that OpenShift issues many spurious notifications for updates when
		// the endpoints set is actually the same, so we may ultimately end up
		// adding and deleting 0 endpoints.

		for member := range members {
			if members[member] {
				needToDelete[member] = true
			}
		}
	}

	// Add pool members for any endpoints in the new set that did not already have
	// endpoints, and update needToDelete for any endpoints in the new set that
	// already have pool members so that we know not to delete those pool members
	// below.
	for _, subset := range endpoints.Subsets {
		for _, addr := range subset.Addresses {
			for _, port := range subset.Ports {
				dest := fmt.Sprintf("%s:%d", addr.IP, port.Port)
				exists := needToDelete[dest]
				needToDelete[dest] = false
				if exists {
					glog.V(4).Infof("  Skipping %s because it already exists.", dest)
				} else {
					glog.V(4).Infof("  Adding %s...", dest)
					err = p.F5Client.AddPoolMember(poolname, dest)
					if err != nil {
						glog.V(4).Infof("  Error adding endpoint %s to pool %s: %v",
							dest, poolname, err)
					}
				}
			}
		}
	}

	// Delete any pool members for which the endpoint no longer exists.
	for member := range needToDelete {
		if needToDelete[member] {
			glog.V(4).Infof("  Deleting %s...", member)
			err = p.F5Client.DeletePoolMember(poolname, member)
			if err != nil {
				glog.V(4).Infof("  Error deleting endpoint %s from pool %s: %v",
					member, poolname, err)
			}
		}
	}

	return nil
}

// deletePool delete the named pool from F5 BIG-IP.
func (p *F5Plugin) deletePool(poolname string) error {
	poolExists, err := p.F5Client.PoolExists(poolname)
	if err != nil {
		glog.V(4).Infof("F5Client.PoolExists failed: %v", err)
		return err
	}

	if poolExists {
		err = p.F5Client.DeletePool(poolname)
		if err != nil {
			glog.V(4).Infof("Error deleting pool %s: %v", poolname, err)
			return err
		}
	}

	return nil
}

// deletePoolIfEmpty deletes the named pool from F5 BIG-IP if, and only if, it
// has no members.
func (p *F5Plugin) deletePoolIfEmpty(poolname string) error {
	poolExists, err := p.F5Client.PoolExists(poolname)
	if err != nil {
		glog.V(4).Infof("F5Client.PoolExists failed: %v", err)
		return err
	}

	if poolExists {
		members, err := p.F5Client.GetPoolMembers(poolname)
		if err != nil {
			glog.V(4).Infof("F5Client.GetPoolMembers failed: %v", err)
			return err
		}

		// We only delete the pool if the pool is empty, which it may not be
		// if a service has been added and has not (yet) been deleted.
		if len(members) == 0 {
			err = p.F5Client.DeletePool(poolname)
			if err != nil {
				glog.V(4).Infof("Error deleting pool %s: %v", poolname, err)
				return err
			}
		}
	}

	return nil
}

// poolName returns a string that can be used as a poolname in F5 BIG-IP and
// is distinct for the given endpoints namespace and name.
func poolName(endpointsNamespace, endpointsName string) string {
	return fmt.Sprintf("openshift_%s_%s", endpointsNamespace, endpointsName)
}

func (p *F5Plugin) checkActive() (bool, error) {
	active, err := p.F5Client.CheckActive()
	if (err == nil) && (! active) {
		// TODO: Check that automatic sync is actually enabled.  If not, run a manual configsync on the devicegroup that /OpenShift partition is attached to, eg. after Commit()'ing the current changeset or in a similar place.
		glog.V(4).Infof("Controlled BIG-IP is HA passive; assuming auto-sync from another unit will apply, skipping update.")
	}
	return active, err
}

// HandleEndpoints processes watch events on the Endpoints resource and
// creates and deletes pools and pool members in response.
func (p *F5Plugin) HandleEndpoints(eventType watch.EventType, endpoints *kapi.Endpoints) error {

	glog.V(4).Infof("Processing %d Endpoints for Name: %v (%v)", len(endpoints.Subsets), endpoints.Name, eventType)

	for i, s := range endpoints.Subsets {
		glog.V(4).Infof("  Subset %d : %#v", i, s)
	}

	active, err := p.checkActive()
	if err != nil {
		return err
	}
	if ! active {
		return nil
	}

	switch eventType {
	case watch.Added, watch.Modified:
		// Name of the pool in F5.
		poolname := poolName(endpoints.Namespace, endpoints.Name)

		if len(endpoints.Subsets) == 0 {
			// F5 does not permit us to delete a pool if it has a rule associated with
			// it.  However, a pool does not necessarily have a rule associated with
			// it because it may be from a service for which no route was created.
			// Thus we first delete the endpoints from the pool, then we try to delete
			// the pool, in case there is no route associated, but if there *is*
			// a route associated though, the delete will fail and we will have to
			// rely on HandleRoute to delete the pool when it deletes the route.

			glog.V(4).Infof("Empty set of subnets for endpoint.  Deleting endpoints for pool %s", poolname)

			err := p.updatePool(poolname, endpoints)
			if err != nil {
				return err
			}

			glog.V(4).Infof("Deleting pool %s", poolname)

			// Note: deletePool will throw errors if the route
			//       has not been deleted as the policy would
			//       still refer to the pool. That is ok as the
			//       pool will still get deleted when the route
			//       gets deleted.
			err = p.deletePool(poolname)
			if err != nil {
				return err
			}
		} else {
			glog.V(4).Infof("Updating or adding endpoints for pool %s", poolname)

			err := p.ensurePoolExists(poolname)
			if err != nil {
				return err
			}

			err = p.updatePool(poolname, endpoints)
			if err != nil {
				return err
			}
		}
	case watch.Deleted:
		poolname := poolName(endpoints.Namespace, endpoints.Name)
		// presumably, the endpoints are a nil subnet now, reset it anyway
		endpoints.Subsets = nil
		err := p.updatePool(poolname, endpoints)
		if err != nil {
			return err
		}

		glog.V(4).Infof("Deleting pool %s", poolname)

		err = p.deletePool(poolname)
		if err != nil {
			return err
		}
	}

	glog.V(4).Infof("Done processing Endpoints for Name: %v.", endpoints.Name)

	return nil
}

// routeName returns a string that can be used as a rule name in F5 BIG-IP and
// is distinct for the given route.
func routeName(route routeapi.Route) string {
	name := controller.GetSafeRouteName(route.Name)
	return fmt.Sprintf("openshift_route_%s_%s", route.Namespace, name)
}

// In order to map OpenShift routes to F5 objects, we must divide routes into
// several types:
//
// • "Insecure" routes, those with no SSL/TLS, are implemented using a profile
//   on the HTTP vserver by creating a rule for each route.
//
// • "Secure" routes, comprising edge and reencrypt routes, are implemented
//   using a profile on the HTTPS vserver and rules on this profile, as well
//   as client SSL profiles and (for reencrypt) server SSL profiles.
//
// • "Passthrough" routes are implemented using an iRule that is associated with
//   the HTTPS vserver.  This iRule parses the SNI protocol and looks the
//   servername up in an F5 data-group to determine the pool for a request.
//   Thus we must maintain a data group that maps hostname to poolname, as well
//   as a data group that maps routename to hostname, so that we can reconstruct
//   that state in the F5 client during initialization from the state that we
//   have stored in F5 BIG-IP.

// addRoute creates route with the given name and parameters and of the suitable
// type (insecure, secure, or passthrough) based on the given TLS configuration.
func (p *F5Plugin) addRoute(routename, poolname, hostname, pathname string,
	tls *routeapi.TLSConfig) error {
	glog.V(4).Infof("Adding route %s...", routename)

	// We will use prettyPathname for log output.
	prettyPathname := pathname
	if prettyPathname == "" {
		prettyPathname = "(any)"
	}

	if tls == nil || len(tls.Termination) == 0 {
		glog.V(4).Infof("Adding insecure route %s for pool %s,"+
			" hostname %s, pathname %s...",
			routename, poolname, hostname, prettyPathname)
		err := p.F5Client.AddInsecureRoute(routename, poolname, hostname, pathname)
		if err != nil {
			glog.V(4).Infof("Error adding insecure route for pool %s: %v", poolname,
				err)
			return err
		}

	} else if tls.Termination == routeapi.TLSTerminationPassthrough {
		glog.V(4).Infof("Adding passthrough route %s for pool %s, hostname %s...",
			routename, poolname, hostname)
		err := p.F5Client.AddPassthroughRoute(routename, poolname, hostname)
		if err != nil {
			glog.V(4).Infof("Error adding passthrough route for pool %s: %v",
				poolname, err)
			return err
		}

	} else {
		glog.V(4).Infof("Adding secure route %s for pool %s,"+
			" hostname %s, pathname %s...",
			routename, poolname, hostname, prettyPathname)
		err := p.F5Client.AddSecureRoute(routename, poolname,
			hostname, prettyPathname)
		if err != nil {
			glog.V(4).Infof("Error adding secure route for pool %s: %v",
				poolname, err)
			return err
		}

		err = p.F5Client.AddCert(routename, hostname, tls.Certificate, tls.Key,
			tls.DestinationCACertificate)
		if err != nil {
			glog.V(4).Infof("Error adding TLS profile for route %s: %v",
				routename, err)
			return err
		}

		if tls.Termination == routeapi.TLSTerminationReencrypt {
			// add to reencrypt dg
			glog.V(4).Infof("Adding re-encrypt route %s for pool %s,"+
				" hostname %s, pathname %s...",
				routename, poolname, hostname, prettyPathname)
			p.F5Client.AddReencryptRoute(routename, poolname, hostname)
		}

		if tls.Termination == routeapi.TLSTerminationEdge && tls.InsecureEdgeTerminationPolicy == routeapi.InsecureEdgeTerminationPolicyRedirect {
			glog.V(4).Infof("Add secure redirect for route %s pool %s, hostname %s, pathname %s", routename, poolname, hostname, prettyPathname)
			err := p.F5Client.AddInsecureRedirectRoute(routename, poolname, hostname, pathname)
			if err != nil {
				glog.V(4).Infof("Error allowing redirect route for pool %s: %v", poolname, err)
				return err
			}
		}

		if tls.Termination == routeapi.TLSTerminationEdge && tls.InsecureEdgeTerminationPolicy == routeapi.InsecureEdgeTerminationPolicyAllow {
			glog.V(4).Infof("Allowing insecure route %s for pool %s, hostname %s, pathname %s...", routename, poolname, hostname, prettyPathname)
			err := p.F5Client.AddInsecureRoute(routename, poolname, hostname, pathname)
			if err != nil {
				glog.V(4).Infof("Error allowing insecure route for pool %s: %v", poolname, err)
				return err
			}
		}
	}

	return nil
}

// deleteRoute deletes the named route from F5 BIG-IP.
func (p *F5Plugin) deleteRoute(routename string) error {
	glog.V(4).Infof("Deleting route %s...", routename)

	// Start with the routes because we cannot delete the pool until we delete
	// any associated profiles and rules.

	secureRouteExists, err := p.F5Client.SecureRouteExists(routename)
	if err != nil {
		glog.V(4).Infof("F5Client.SecureRouteExists failed: %v", err)
		return err
	}

	if secureRouteExists {
		glog.V(4).Infof("Deleting SSL profiles for secure route %s...", routename)

		err := p.F5Client.DeleteCert(routename)
		if err != nil {
			f5err, ok := err.(RestError)
			if ok && f5err.httpStatusCode == 404 {
				glog.V(4).Infof("Secure route %s does not have TLS/SSL configured.",
					routename)
			} else {
				glog.V(4).Infof("Error deleting SSL profiles for secure route %s: %v",
					routename, err)
				// Presumably the profiles still exist, so we cannot delete the route.
				return err
			}
		}

		glog.V(4).Infof("Deleting secure route %s...", routename)
		err = p.F5Client.DeleteSecureRoute(routename)
		if err != nil {
			f5err, ok := err.(RestError)
			if ok && f5err.httpStatusCode == 404 {
				glog.V(4).Infof("Secure route for %s does not exist.", routename)
			} else {
				glog.V(4).Infof("Error deleting secure route %s: %v", routename, err)
				// Presumably the route still exists, so we cannot delete the pool.
				return err
			}
		}
	}

	insecureRouteExists, err := p.F5Client.InsecureRouteExists(routename)
	if err != nil {
		glog.V(4).Infof("F5Client.InsecureRouteExists failed: %v", err)
		return err
	}

	if insecureRouteExists {
		glog.V(4).Infof("Deleting insecure route %s...", routename)
		err := p.F5Client.DeleteInsecureRoute(routename)
		if err != nil {
			f5err, ok := err.(RestError)
			if ok && f5err.httpStatusCode == 404 {
				glog.V(4).Infof("Insecure route for %s does not exist.", routename)
			} else {
				glog.V(4).Infof("Error deleting insecure route %s: %v", routename, err)
				// Presumably the route still exists, so we cannot delete the pool.
				return err
			}
		}
	}

	passthroughRouteExists, err := p.F5Client.PassthroughRouteExists(routename)
	if err != nil {
		glog.V(4).Infof("F5Client.PassthroughRouteExists failed: %v", err)
		return err
	}

	if passthroughRouteExists {
		err = p.F5Client.DeletePassthroughRoute(routename)
		if err != nil {
			f5err, ok := err.(RestError)
			if ok && f5err.httpStatusCode == 404 {
				glog.V(4).Infof("Passthrough route %s does not exist.",
					routename)
			} else {
				glog.V(4).Infof("Error deleting passthrough route %s: %v",
					routename, err)
				// Don't continue if we could not clean up the passthrough route.
				return err
			}
		}
	} else {
		reencryptRouteExists, err := p.F5Client.ReencryptRouteExists(routename)
		if err != nil {
			glog.V(4).Infof("F5Client.ReencryptRouteExists failed: %v", err)
			return err
		}

		if reencryptRouteExists {
			err = p.F5Client.DeleteReencryptRoute(routename)
			if err != nil {
				f5err, ok := err.(RestError)
				if ok && f5err.httpStatusCode == 404 {
					glog.V(4).Infof("Reencrypt route %s does not exist.",
						routename)
				} else {
					glog.V(4).Infof("Error deleting reencrypt route %s: %v",
						routename, err)
					// Don't continue if we could not clean up the reencrypt route.
					return err
				}
			}
		}
	}

	return nil
}

func getNodeIP(node *kapi.Node) (string, error) {
	if len(node.Status.Addresses) > 0 && node.Status.Addresses[0].Address != "" {
		return node.Status.Addresses[0].Address, nil
	} else {
		return netutils.GetNodeIP(node.Name)
	}
}

func (p *F5Plugin) HandleNamespaces(namespaces sets.String) error {
	return fmt.Errorf("namespace limiting for F5 is not implemented")
}

func (p *F5Plugin) HandleNode(eventType watch.EventType, node *kapi.Node) error {
	// The F5 appliance, if hooked to use the VxLAN encapsulation
	// should have its FDB updated depending on nodes arriving and leaving the cluster
	switch eventType {
	case watch.Added, watch.Modified:
		// New VTEP created, add the record to the vxlan fdb
		ip, err := getNodeIP(node)
		if err != nil {
			// just log the error
			glog.Warningf("Error in obtaining IP address of newly added node %s - %v", node.Name, err)
			return nil
		}

		// check and find if the node has already been processed
		// if yes, then break, or just add the new vtep
		uid := node.ObjectMeta.UID
		if oldNodeIP, ok := p.VtepMap[uid]; ok && (oldNodeIP == ip) {
			glog.V(4).Infof("Skipping update for node %s; IP and UID matches cached entry.", node.Name)
			break
		}
		err = p.F5Client.AddVtep(ip)
		if err != nil {
			glog.Errorf("Error in adding node '%s' to F5s FDB - %v", ip, err)
			return err
		}
		p.VtepMap[uid] = ip
	case watch.Deleted:
		// VTEP deleted, delete the record from vxlan fdb
		ip, err := getNodeIP(node)
		if err != nil {
			// just log the error
			glog.Warningf("Error in obtaining IP address of deleted node %s - %v", node.Name, err)
			return nil
		}
		err = p.F5Client.RemoveVtep(ip)
		if err != nil {
			glog.Errorf("Error in removing node '%s' from F5s FDB - %v", ip, err)
			return err
		}
		uid := node.ObjectMeta.UID
		delete(p.VtepMap, uid)
	}
	return nil
}

// HandleRoute processes watch events on the Route resource and
// creates and deletes policy rules in response.
func (p *F5Plugin) HandleRoute(eventType watch.EventType, route *routeapi.Route) error {
	glog.V(4).Infof("Processing route for service: %v (%v)", route.Spec.To, route)

	active, err := p.checkActive()
	if err != nil {
		return err
	}
	if ! active {
		return nil
	}

	// Name of the pool in F5.
	poolname := poolName(route.Namespace, route.Spec.To.Name)

	// Virtual hostname for policy rule in F5.
	hostname := route.Spec.Host

	// Pathname for the policy rule in F5.
	pathname := route.Spec.Path

	// Name for the route in F5.
	routename := routeName(*route)

	switch eventType {
	case watch.Deleted:

		err := p.deleteRoute(routename)
		if err != nil {
			return err
		}

		err = p.deletePoolIfEmpty(poolname)
		if err != nil {
			return err
		}

	case watch.Added, watch.Modified:
		glog.V(4).Infof("Updating or adding route %s...", routename)

		// F5 does not permit us to create a rule without a pool, so we need to
		// create the pool here in HandleRoute if it does not already exist.
		// However, the pool may have already been created by HandleEndpoints.
		err := p.ensurePoolExists(poolname)
		if err != nil {
			return err
		}

		err = p.addRoute(routename, poolname, hostname, pathname, route.Spec.TLS)
		if err != nil {
			return err
		}
	}

	glog.V(4).Infof("Done processing route %s.", routename)

	return nil
}

// No-op since f5 configuration can be updated piecemeal
func (p *F5Plugin) Commit() error {
	return nil
}
