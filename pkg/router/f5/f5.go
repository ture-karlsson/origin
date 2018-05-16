package f5

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"regexp"
	"time"

	"github.com/golang/glog"
	knet "k8s.io/apimachinery/pkg/util/net"
)

const (
	F5DefaultPartitionPath = "/OpenShift"

	tunnelName = "vxlan5000"

	monitorName = "openshift-pod-monitor"

	clientSslTemplateProfileName = "openshift-clientssl"

	serverSslTemplateProfileName = "openshift-serverssl"

	// LTM policy for HTTP routes.
	httpPolicyName = "openshift_insecure_routes"

	// LTM policy for HTTPS routes.
	httpsPolicyName = "openshift_secure_routes"

	// Maps hostname to poolname for SSL bridging, used to select pool based on hostname.
	reencryptHostsDataGroupName = "ssl_reencrypt_servername_dg"

	// Maps routename to hostname, used for re-initializing plugin state after pod restart.
	reencryptRoutesDataGroupName = "ssl_reencrypt_route_dg"

	// Maps hostname to poolname for SSL bypass, used to select pool based on hostname.
	passthroughHostsDataGroupName = "ssl_passthrough_servername_dg"

	// Maps routename to hostname, used for re-initializing plugin state after pod restart.
	passthroughRoutesDataGroupName = "ssl_passthrough_route_dg"

)

// Pretty-printer for HTTP and iControl REST errors.
func (err RestError) Error() string {
	msg := ""
	msg += fmt.Sprintf("HTTP code: %d", err.httpStatusCode)
	if err.Message != nil {
		msg += fmt.Sprintf("; iControl REST error message: %s", *err.Message)
	}
	if err.err != nil {
		msg += fmt.Sprintf("; error: %v", err.err)
	}
	return fmt.Sprintf("Encountered an error on %s request to URL %s: %s", err.verb, err.url, msg)
}

// passthroughRoute represents a passthrough route for the F5 router's internal
// state.  In the F5 BIG-IP host itself, we must store this information using
// two datagroups: one that makes routename to hostname so that we can
// reconstruct this state when initializing the router, and one that maps
// hostname to poolname for use by the iRule that handles passthrough routes.
type passthroughRoute struct {
	hostname string
	poolname string
}

// reencryptRoute represents a reencrypt route for the F5 router's internal state
// similar to the passthrough route
type reencryptRoute struct {
	hostname string
	poolname string
}

// State of the running plugin instance.  Should be in sync with the connected BIG-IP, once plugin cache is warm.
type f5LTM struct {
	f5LTMCfg

	// poolMembers maps pool name to set of pool members, where the pool
	// name is a string and the set of members of a pool is represented by
	// a map with value type bool.  A pool member will be identified by
	// a string of the format "ipaddress:port".
	poolMembers map[string]map[string]bool

	// routes maps vserver name to set of routes.
	routes map[string]map[string]bool

	// passthroughRoutes maps routename to passthroughroute{hostname, poolname}.
	passthroughRoutes map[string]passthroughRoute

	// reencryptRoutes maps routename to passthroughroute{hostname, poolname}.
	reencryptRoutes map[string]reencryptRoute

	// Caches the configured hostname of the BIG-IP unit.
	hostname string

	// Caches the traffic group associated with our partition.
	trafficGroup string

	// Last HA status, used to detect transitions between HA active and passive.
	isActive bool
}

// Contains the configuration used when launching this plugin instance.
type f5LTMCfg struct {
	// Hostname or IP address of BIG-IP.  For example local-only self-ip with port lockdown set to allow 443/tcp.
	host string

	// To verify against alternate CA certificates or a self-signed certificate with the CA flag.
	cabundle string

	// To verify certificates with a hostname that does not match what is in the host field (above), put the certificate hostname here.
	althostname string

	// Service user account name as configured on BIG-IP.  Must at least be Manager on the relevant partition.
	username string

	// Password for the service user account.
	// *IMPORTANT*: It is up to the OpenShift administrator to ensure that the environment variable this comes from is loaded through a Secrets volume.
	password string

	// Partition and path for storing configuration on BIG-IP.
	// Partitions are normally used to create an access control boundary for BIG-IP users and applications.
	partitionPath string

	// If true, connect the BIG-IP to openshift-sdn via VXLAN by programming the FDB on BIG-IP.
	enableVxlan bool

	// Name of virtual server that handles ingress HTTP traffic.
	httpVserver string

	// Name of virtual server that handles ingress HTTPS traffic.
	httpsVserver string
}

// Makes a new f5LTM object given a f5LTMCfg object.
func newF5LTM(cfg f5LTMCfg) (*f5LTM, error) {
	// Ensure the configuration has a non-empty partition name.
	partitionPath := F5DefaultPartitionPath
	if len(cfg.partitionPath) > 0 {
		partitionPath = cfg.partitionPath
	}

	// Ensure partition path is absolute.
	partitionPath = path.Join("/", partitionPath)

	if cfg.cabundle != "" {
		glog.Warning("CA bundle used for TLS validation:\n", cfg.cabundle)
	}

	if cfg.althostname != "" {
		glog.Warning("Hostname used for TLS validation: ", cfg.althostname)
	}

	if cfg.httpVserver == "" {
		glog.Warning("No virtual server name specified for HTTP; HTTP routes will not be configured")
	}

	if cfg.httpsVserver == "" {
		glog.Warning("No virtual server name specified for HTTPS; HTTPS routes will not be configured")
	}

	if ! cfg.enableVxlan {
		glog.Warning("No VXLAN option specified; VXLAN FDB programming disabled")
	}

	if len(cfg.partitionPath) == 0 {
		glog.Warningf("No partition specified; using default: %s", partitionPath)
	}

	router := &f5LTM{
		f5LTMCfg: f5LTMCfg{
			host: cfg.host,
			cabundle: cfg.cabundle,
			althostname: cfg.althostname,
			username: cfg.username,
			password: cfg.password,
			partitionPath: partitionPath,
			enableVxlan: cfg.enableVxlan,
			httpVserver: cfg.httpVserver,
			httpsVserver: cfg.httpsVserver,
		},
		poolMembers: map[string]map[string]bool{},
		routes:      map[string]map[string]bool{},
		isActive:    false,
		hostname:    "",
		trafficGroup: "",
	}

	return router, nil
}

//
// Helper routines for REST calls.
//

// restRequest makes a REST request to the F5 BIG-IP iControl REST API.
//
// One of three things can happen as a result of an iControl request:
//
// (1) The request succeeds and returns a HTTP 200 response with a JSON payload
//     that has a "kind" field with the data type (for example "tm:ltm:pool"),
//     or, as a special case for DELETE, no payload at all.
//     In this case, restRequest decodes the payload into the result argument,
//     if specified by the caller, and returns nil (no error).
//
// (2) The request fails and returns an HTTP 4xx or 5xx response with a JSON
//     payload that has a "code" field with a numeric code matching the HTTP
//     response code, and a "message" field with a string message.
//     In this case, restRequest decodes the error and returns it (and does
//     not touch the result argument).
//
// (3) Something went wrong and JSON could not be decoded from the response
//     body, ie. because it was unexpectedly empty, or it was actually HTML,
//     or it was missing fields that you would expect from iControl REST.
//     In this case, restRequest returns a more generic error.
func (f5 *f5LTM) restRequest(verb string, url string, payload io.Reader, filesize int, result interface{}) error {
	// Set up TLS verification parameters.
	cfg := &tls.Config{}
	if f5.cabundle != "" {
		cfg.RootCAs = x509.NewCertPool()
		cfg.RootCAs.AppendCertsFromPEM([]byte(f5.cabundle))
	}
	if f5.althostname != "" {
		cfg.ServerName = f5.althostname
	}
	tr := knet.SetTransportDefaults(&http.Transport{TLSClientConfig: cfg})

	// Create struct instance to hold error response, filled in as we go along.
	errorResult := RestError{verb: verb, url: url}

	// Create a new HTTP request instance, using the request payload reader given by caller.
	req, err := http.NewRequest(verb, url, payload)
	if err != nil {
		errorResult.err = fmt.Errorf("http.NewRequest failed: %v", err)
		return errorResult
	}

	// Guess whether this is a temporary file upload or a JSON request.
	upload := filesize > 0

	// Set appropriate HTTP headers including authentication.
	req.SetBasicAuth(f5.username, f5.password)
	req.Header.Set("Accept", "application/json")
	if ! upload {
		req.Header.Set("Content-Type", "application/json")
	} else {
		glog.V(4).Infof("Uploading file of size %d...", filesize)
		req.Header.Set("Content-Type", "application/octet-stream")
		// TODO: If file size above 1MB, must be chunked into separate requests, and header set for each chunk:
		req.Header.Set("Content-Range", fmt.Sprintf("%d-%d/%d", 0, filesize - 1, filesize))
		// Example for a 1K file in one chunk: Content-Range: 0-1023/1024
	}

	// Disable redirect-following, so credentials are only sent to the known endpoint.
	redirHandler := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Add a timeout to prevent deadlocks in case ie. a firewall starts dropping segments.
	timeout := 60 * time.Second

	// Create a HTTP client on top of the TLS transport.
	client := &http.Client{Transport: tr, CheckRedirect: redirHandler, Timeout: timeout}

	// Redact credentials from log output.
	details := fmt.Sprintf("%v", req)
	re := regexp.MustCompile(`Authorization:\[Basic [^\]]+\]`)
	redacted := re.ReplaceAllString(details, "Authorization:[Basic ********]")

	// Queue the HTTP request onto the HTTP client.
	glog.V(4).Infof("Sending request: %s\n", redacted)
	resp, err := client.Do(req)
	if err != nil {
		// Certificate validation errors usually occur here.
		errorResult.err = fmt.Errorf("client.Do failed: %v", err)
		return errorResult
	}
	defer resp.Body.Close()

	// Read HTTP status code.
	errorResult.httpStatusCode = resp.StatusCode

	// Create a JSON decoder for the response body.
	decoder := json.NewDecoder(resp.Body)

	// Detect authentication failures.
	if resp.StatusCode == http.StatusUnauthorized {
		// For some reason, authentication errors have HTML payload, ignore.
		errorResult.err = fmt.Errorf("Authentication failed.  Wrong username/password?")
		return errorResult
	}

	// Attempt decoding of other errors, with JSON payload.
	if resp.StatusCode >= http.StatusBadRequest {
		err = decoder.Decode(&errorResult)
		if err != io.EOF {
			errorResult.err = fmt.Errorf("Decoder.Decode failed: %v", err)
		} else {
			errorResult.err = fmt.Errorf("Missing JSON payload in error response")
		}
		return errorResult
	}

	// Attempt decoding of success payload.
	if result != nil {
		err = decoder.Decode(result)
		if err != nil {
			if err != io.EOF {
				errorResult.err = fmt.Errorf("Decoder.Decode failed: %v", err)
			} else {
				errorResult.err = fmt.Errorf("Missing JSON payload in success response")
			}
			return errorResult
		}
	}

	// No response payload expected by caller and no HTTP error seen, assume OK.
	return nil
}

// Helper for iControl operations that take a payload.
func (f5 *f5LTM) restRequestPayload(verb string, url string, payload interface{}, result interface{}) error {
	jsonStr, err := json.Marshal(payload)
	if err != nil {
		return RestError{verb: verb, url: url, err: err}
	}

	encodedPayload := bytes.NewBuffer(jsonStr)
	return f5.restRequest(verb, url, encodedPayload, -1, result)
}

// Issues a GET request against the iControl REST API.
func (f5 *f5LTM) get(url string, result interface{}) error {
	return f5.restRequest("GET", url, nil, -1, result)
}

// Issues a POST request against the iControl REST API.
func (f5 *f5LTM) post(url string, payload interface{}, result interface{}) error {
	return f5.restRequestPayload("POST", url, payload, result)
}

// Issues a PATCH request against the iControl REST API.
func (f5 *f5LTM) patch(url string, payload interface{}, result interface{}) error {
	return f5.restRequestPayload("PATCH", url, payload, result)
}

// Issues a DELETE request against the iControl REST API.
func (f5 *f5LTM) delete(url string, result interface{}) error {
	return f5.restRequest("DELETE", url, nil, -1, result)
}

// Dumps a temporary file on the BIG-IP via the iControl REST API.
func (f5 *f5LTM) upload(filename string, body []byte, result interface{}) error {
	url := fmt.Sprintf("https://%s/mgmt/shared/file-transfer/uploads/%s", f5.host, filename)
	payload := bytes.NewReader(body)
	return f5.restRequest("POST", url, payload, len(body), result)
}

//
// iControl REST resource helper methods.
//

// Encode folder names (partition and path), ie. /Common/foo becomes ~Common~foo in the iControl URI.
// Example API URI: https://<ip>:<port>/mgmt/tm/ltm/policy/~Common~foo/rules
func encodeiControlUriPathComponent(pathName string) string {
	return strings.Replace(pathName, "/", "~", -1)
}

// See comments regarding encodeiControlUriPathComponent().
func (f5 *f5LTM) iControlUriResourceId(resourceName string) string {
	resourcePath := path.Join(f5.partitionPath, resourceName)
	return encodeiControlUriPathComponent(resourcePath)
}

func isConflict(err error) bool {
	re, ok := err.(RestError)
	if ! ok {
		return false
	}
	return re.httpStatusCode == http.StatusConflict
}

func isGone(err error) bool {
	re, ok := err.(RestError)
	if ! ok {
		return false
	}
	return re.httpStatusCode == http.StatusNotFound
}

func isReferenced(err error) bool {
	re, ok := err.(RestError)
	if ! ok {
		return false
	}
	if re.Message == nil {
		return false
	}
	// See K23011574 as reference to error code.
	if ! strings.HasPrefix(*re.Message, "01070265:3:") {
		return false
	}
	return re.httpStatusCode == http.StatusBadRequest
}

func (f5 *f5LTM) IsReferenced(err error) bool {
	return isReferenced(err)
}

//
// Routines for controlling F5.
//

func (f5 *f5LTM) Initialize() error {
	//
	// Initialize is responsible for creating static configuration on the BIG-IP.
	//
	// Currently does nothing.  Use "tmsh" commands to create prerequisite configuration items.
	//
	return nil
}

// Retrieve hostname setting of F5 BIG-IP unit.
func (f5 *f5LTM) ensureUnitHostname() (string, error) {
	if f5.hostname == "" {
		// Note: we minimize REST calls by assuming this does not change; manually restart plugin if it does.
		url := fmt.Sprintf("https://%s/mgmt/tm/sys/global-settings", f5.host)
		res := f5GlobalSettings{}
		err := f5.get(url, &res)
		if err != nil {
			return "", err
		}
		if res.Hostname == "" {
			err := fmt.Errorf("Error: Invalid hostname %s configured for BIG-IP", res.Hostname)
			return "", err
		}
		// Note: references to a BIG-IP unit seems to use Common as the partition for the device object given its hostname.
		abs := "/Common/" + res.Hostname
		glog.Infof("Hostname is: %s", abs)
		f5.hostname = abs
	}
	return f5.hostname, nil
}

// Retrieve associated traffic-group for a folder on F5 BIG-IP unit.
func (f5 *f5LTM) ensureFolderTrafficGroup() (string, error) {
	if f5.trafficGroup == "" {
		// Note: we minimize REST calls by assuming this does not change; manually restart plugin if it does.
		url := fmt.Sprintf("https://%s/mgmt/tm/sys/folder/%s", f5.host, f5.iControlUriResourceId(""))
		res := f5SysFolder{}
		err := f5.get(url, &res)
		if err != nil {
			return "", err
		}
		if res.TrafficGroup == "none" {
			err := fmt.Errorf("Error: Invalid traffic group %s for partition %s", res.TrafficGroup, f5.partitionPath)
			return "", err
		}
		glog.Infof("Traffic group for partition %s is: %s", f5.partitionPath, res.TrafficGroup)
		f5.trafficGroup = res.TrafficGroup
	}
	return f5.trafficGroup, nil
}

// Retrieve active/passive flag for traffic-group on a given F5 BIG-IP unit by querying the controlled unit.
func (f5 *f5LTM) trafficGroupStatus(host, group string) (bool, error) {
	url := fmt.Sprintf("https://%s/mgmt/tm/cm/traffic-group/%s/stats", f5.host, encodeiControlUriPathComponent(group))
	res := f5CmTrafficGroupAllDevicesStatus{}
	err := f5.get(url, &res)
	if err != nil {
		return false, err
	}
	for _, entry := range res.Entries {
		props := entry.Nested.Properties
		pDev := props.DeviceName.Value
		pGrp := props.TrafficGroup.Value
		if pDev != host {
			glog.V(4).Infof("No-match for dev %s (maybe peer device)", pDev)
			continue
		}
		if pGrp != group {
			glog.V(4).Infof("No-match for tg %s (maybe unrelated traffic-group)", pGrp)
			continue
		}
		fs := props.FailoverState.Value
		if fs == "active" {
			return true, nil
		}
		if fs == "standby" {
			return false, nil
		}
		err = fmt.Errorf("Error: Invalid failover state %s for traffic group %s on host %s", fs, group, host)
		return false, err
	}
	err = fmt.Errorf("Error: Device with hostname %s not found in status for traffic group %s", host, group)
	return false, err
}

// Check for HA active flag.
func (f5 *f5LTM) CheckActive() (bool, error) {
	host, err := f5.ensureUnitHostname()
	if err != nil {
		return false, err
	}

	tg, err := f5.ensureFolderTrafficGroup()
	if err != nil {
		return false, err
	}

	gs, err := f5.trafficGroupStatus(host, tg)
	if err != nil {
		return false, err
	}
	glog.Infof("HA status is: %t", gs)

	if gs == f5.isActive {
		return f5.isActive, nil
	}
	f5.isActive = gs

	if f5.isActive {
		glog.Warningf("Going active and clearing cache")
		f5.poolMembers = map[string]map[string]bool{}
		f5.routes = map[string]map[string]bool{}
		f5.reencryptRoutes = nil
		f5.passthroughRoutes = nil
	} else {
		glog.Warningf("Going standby")
	}
	return f5.isActive, nil
}

// Encode OpenShift host IP / VTEP IP into a corresponding MAC address.
func checkIPAndGetMac(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		errStr := fmt.Sprintf("vtep IP '%s' is not a valid IP address", ipStr)
		glog.Warning(errStr)
		return "", fmt.Errorf(errStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		errStr := fmt.Sprintf("vtep IP '%s' is not a valid IPv4 address", ipStr)
		glog.Warning(errStr)
		return "", fmt.Errorf(errStr)
	}
	macAddr := fmt.Sprintf("0a:0a:%02x:%02x:%02x:%02x", ip4[0], ip4[1], ip4[2], ip4[3])
	return macAddr, nil
}

// Given an OpenShift host IP / VTEP IP, add it to the FDB on the relevant VXLAN tunnel (normally VNID 0).
func (f5 *f5LTM) AddVtep(ipStr string) error {
	if ! f5.enableVxlan {
		return nil
	}
	macAddr, err := checkIPAndGetMac(ipStr)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/mgmt/tm/net/fdb/tunnel/%s~%s/records", f5.host, strings.Replace(f5.partitionPath, "/", "~", -1), tunnelName)
	payload := f5AddFDBRecordPayload{
		Name:     macAddr,
		Endpoint: ipStr,
	}
	glog.Infof("Adding fdb entry for %s.", ipStr)
	err = f5.post(url, payload, nil)
	if err != nil {
		if ! isConflict(err) {
			return err
		}
	}
	return nil
}

// Remove FDB entry added via AddVtep().
func (f5 *f5LTM) RemoveVtep(ipStr string) error {
	if ! f5.enableVxlan {
		return nil
	}
	macAddr, err := checkIPAndGetMac(ipStr)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/mgmt/tm/net/fdb/tunnel/%s~%s/records/%s", f5.host, strings.Replace(f5.partitionPath, "/", "~", -1), tunnelName, macAddr)
	glog.Infof("Removing fdb entry for %s.", ipStr)
	err = f5.delete(url, nil)
	if err != nil {
		if isGone(err) {
			return nil
		}
	}
	return err
}

// Create a pool with the given name on BIG-IP.
func (f5 *f5LTM) CreatePool(poolname string) error {
	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/pool", f5.host)

	payload := f5Pool{
		Mode:      "round-robin",
		Monitor:   f5.partitionPath + "/" + monitorName,
		Partition: f5.partitionPath,
		Name:      poolname,
	}

	glog.Infof("Creating pool %s.", poolname)
	err := f5.post(url, payload, nil)
	if err != nil {
		return err
	}

	// Put the newly created pool in the cache too, to save one REST call later.
	f5.poolMembers[poolname] = map[string]bool{}

	glog.V(4).Infof("Pool %s created.", poolname)

	return nil
}

// Delete the specified pool from BIG-IP, and remove f5.poolMembers[poolname].
func (f5 *f5LTM) DeletePool(poolname string) error {
	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/pool/%s", f5.host, f5.iControlUriResourceId(poolname))

	glog.Infof("Deleting pool %s.", poolname)
	err := f5.delete(url, nil)
	if err != nil {
		if ! isGone(err) {
			return err
		}
	}

	// Note: We *must* use delete here rather than merely assigning false because
	// len() includes false items, and we want len() to return an accurate count
	// of members.  Also, we probably save some memory by using delete.
	delete(f5.poolMembers, poolname)

	glog.V(4).Infof("Pool %s deleted.", poolname)

	return nil
}

// Return cached f5.poolMembers[poolname], loading it from BIG-IP if not found.
func (f5 *f5LTM) GetPoolMembers(poolname string) (map[string]bool, error) {
	members, ok := f5.poolMembers[poolname]
	if ok {
		return members, nil
	}

	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/pool/%s/members", f5.host, f5.iControlUriResourceId(poolname))

	res := f5PoolMemberset{}

	err := f5.get(url, &res)
	if err != nil {
		return nil, err
	}

	// Note that we do not initialise f5.poolMembers[poolname] unless we know that
	// the pool exists (i.e., the above GET request for the pool succeeds).
	// (On the other hand, if the GET fails with a 404, we do not remove the pool from cache, for some reason.)
	f5.poolMembers[poolname] = map[string]bool{}

	for _, member := range res.Members {
		f5.poolMembers[poolname][member.Name] = true
	}

	return f5.poolMembers[poolname], nil
}

// Same as GetPoolMembers() except just a boolean is returned indicating if any members were found.
func (f5 *f5LTM) PoolExists(poolname string) (bool, error) {
	_, err := f5.GetPoolMembers(poolname)
	if err == nil {
		return true, nil
	}

	if isGone(err) {
		return false, nil
	}

	return false, err
}

// Check whether the given member is in the specified pool.
func (f5 *f5LTM) PoolHasMember(poolname, member string) (bool, error) {
	members, err := f5.GetPoolMembers(poolname)
	if err != nil {
		return false, err
	}

	return members[member], nil
}

// Add the given member to the specified pool, also updates cache.
func (f5 *f5LTM) AddPoolMember(poolname, member string) error {
	hasMember, err := f5.PoolHasMember(poolname, member)
	if err != nil {
		return err
	}
	if hasMember {
		glog.V(4).Infof("Pool %s already has member %s.\n", poolname, member)
		return nil
	}

	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/pool/%s/members", f5.host, f5.iControlUriResourceId(poolname))

	payload := f5PoolMember{
		Name: member,
	}

	glog.Infof("Adding pool member %s to pool %s.", member, poolname)
	err = f5.post(url, payload, nil)
	if err != nil {
		if ! isConflict(err) {
			return err
		}
	}

	members, err := f5.GetPoolMembers(poolname)
	if err != nil {
		return err
	}

	members[member] = true

	glog.V(4).Infof("Added pool member %s to pool %s.", member, poolname)

	return nil
}

// Delete the given member from the specified pool and update cache.
func (f5 *f5LTM) DeletePoolMember(poolname, member string) error {
	// The invocation of f5.PoolHasMember has the side effect that it will
	// initialise f5.poolMembers[poolname], which is used below, if necessary.
	hasMember, err := f5.PoolHasMember(poolname, member)
	if err != nil {
		return err
	}
	if ! hasMember {
		glog.V(4).Infof("Pool %s does not have member %s.\n", poolname, member)
		return nil
	}

	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/pool/%s/members/%s", f5.host, f5.iControlUriResourceId(poolname), member)

	glog.Infof("Removing pool member %s from pool %s.", member, poolname)
	err = f5.delete(url, nil)
	if err != nil {
		if ! isGone(err) {
			return err
		}
	}

	delete(f5.poolMembers[poolname], member)

	glog.V(4).Infof("Pool member %s deleted from pool %s.", member, poolname)

	return nil
}

// getRoutes returns f5.routes[policyname], first initializing it from F5 if it
// is zero.
func (f5 *f5LTM) getRoutes(policyname string) (map[string]bool, error) {
	routes, ok := f5.routes[policyname]
	if ok {
		return routes, nil
	}

	url := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules", f5.host, f5.iControlUriResourceId(policyname))

	res := f5PolicyRuleset{}

	err := f5.get(url, &res)
	if err != nil {
		return nil, err
	}

	routes = map[string]bool{}

	for _, rule := range res.Rules {
		routes[rule.Name] = true
	}

	f5.routes[policyname] = routes

	return routes, nil
}

// routeExists checks whether the an F5 profile rule exists for the specified
// route.  Note that routeExists assumes that the route name will be the same
// as the rule name.
func (f5 *f5LTM) routeExists(policyname, routename string) (bool, error) {
	routes, err := f5.getRoutes(policyname)
	if err != nil {
		return false, err
	}

	return routes[routename], nil
}

// InsecureRouteExists checks whether the specified insecure route exists.
func (f5 *f5LTM) InsecureRouteExists(routename string) (bool, error) {
	return f5.routeExists(httpPolicyName, routename)
}

// SecureRouteExists checks whether the specified secure route exists.
func (f5 *f5LTM) SecureRouteExists(routename string) (bool, error) {
	return f5.routeExists(httpsPolicyName, routename)
}

// ReencryptRouteExists checks whether the specified reencrypt route exists.
func (f5 *f5LTM) ReencryptRouteExists(routename string) (bool, error) {
	routes, err := f5.getReencryptRoutes()
	if err != nil {
		return false, err
	}

	_, ok := routes[routename]

	return ok, nil
}

// PassthroughRouteExists checks whether the specified passthrough route exists.
func (f5 *f5LTM) PassthroughRouteExists(routename string) (bool, error) {
	routes, err := f5.getPassthroughRoutes()
	if err != nil {
		return false, err
	}

	_, ok := routes[routename]

	return ok, nil
}

// addRoute adds a new rule to the specified F5 policy.  This rule will compare
// the virtual host and URL path of incoming requests against the given hostname
// and pathname (if one is specified).  When the rule matches a request, it will
// route the request to the specified pool.
//
// addRoute re-uses the name of the OpenShift route as the name of the F5
// policy rule.  The rule name must be safe to use in JSON and in URLs (for
// example, slashes or backslashes would cause problems), but this condition
// is met when using the route name because it has the form
// openshift_<namespace>_<servicename>, a namespace must match the regex
// /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/, and service name must match the regex
// /^[a-z]([-a-z0-9]+)?$/.
func (f5 *f5LTM) addRoute(policyname, routename, poolname, hostname, pathname string, redirect bool) error {
	success := false

	policyResourceId := f5.iControlUriResourceId(policyname)
	rulesUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules", f5.host, policyResourceId)

	rulesPayload := f5Rule{
		Name: routename,
	}

	glog.Infof("Adding rule %s to policy %s.", policyname, routename)
	err := f5.post(rulesUrl, rulesPayload, nil)
	if err != nil {
		if isConflict(err) {
			glog.V(4).Infof("Rule %s already exists; skipping...", routename)
		} else {
			glog.Warningf("Failed to add rule: %s", err.Error())
			return err
		}
	}

	// If adding the condition or action to the rule fails later on, delete the rule.
	defer func() {
		if success != true {
			glog.Warningf("Undoing all created objects due to previous failures in addRoute()...")
			err := f5.deleteRoute(policyname, routename)
			if err != nil {
				if ! isGone(err) {
					glog.V(4).Infof("Warning: Creating rule %s failed, and then cleanup got an error: %v", routename, err)
				}
			}
		}
	}()

	conditionUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules/%s/conditions", f5.host, policyResourceId, routename)

	conditionPayload := f5RuleCondition{
		Name:            "0",
		CaseInsensitive: true,
		HttpHost:        true,
		Host:            true,
		Index:           0,
		Equals:          true,
		Request:         true,
		Values:          []string{hostname},
	}

	glog.Infof("Adding/updating condition %s of rule %s in policy %s.", conditionPayload.Name, policyname, routename)
	err = f5.post(conditionUrl, conditionPayload, nil)
	if err != nil {
		// Note: Seems that a HTTP conflict does not happen if the Condition already exists.
		glog.Warningf("Failed to add/update condition: %s", err.Error())
		return err
	}

	// Split path into segments.
	segments := strings.Split(pathname, "/")

	// Remove any empty trailing segments by snipping last element until
	// non-empty segment encountered or just left-most segment is left.
	for {
		if len(segments) <= 1 {
			break
		}
		if len(segments[len(segments) - 1]) > 0 {
			break
		}
		segments = append(segments[:len(segments) - 1])
	}

	// Remove segment 0; it is always empty, since OpenShift enforces paths starting with a forward slash.
	if len(segments) > 0 {
		segments = segments[1:]
	}

	// Reset condition payload and set HTTP URI matching flag.
	conditionPayload.HttpHost = false
	conditionPayload.Host = false
	conditionPayload.HttpUri = true

	// Each segment of the pathname is added to the rule as a separate condition.
	for i, segment := range segments {
		conditionPayload.Name = fmt.Sprintf("%d", i + 1)
		if segment == "" {
			// A no-op condition is necessary for later updates to work correctly.
			conditionPayload.PathSegment = false
			conditionPayload.Equals = false
			conditionPayload.Path = true
			conditionPayload.StartsWith = true
			conditionPayload.Values = []string{"/"}
			conditionPayload.Index = 0
		} else {
			// Regular path segment.
			conditionPayload.PathSegment = true
			conditionPayload.Equals = true
			conditionPayload.Path = false
			conditionPayload.StartsWith = false
			conditionPayload.Values = []string{segment}
			conditionPayload.Index = i + 1
		}
		glog.Infof("Adding/updating condition segment %d: %s.", i + 1, segment)
		err = f5.post(conditionUrl, conditionPayload, nil)
		if err != nil {
			glog.Warningf("Failed to add/update condition segment: %s", err.Error())
			return err
		}
	}

	// During update, remove any superfluous segment conditions from before the update.
	i := len(segments)
	for {
		segmentUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules/%s/conditions/%d", f5.host, policyResourceId, routename, i + 1)
		glog.Infof("Deleting condition segment %d.", i + 1)
		err = f5.delete(segmentUrl, nil)
		if err != nil {
			if ! isGone(err) {
				glog.Warningf("Failed to delete condition segment: %s", err.Error())
				return err
			} else {
				break
			}
		}
		i++
	}

	actionUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules/%s/actions", f5.host, policyResourceId, routename)

	var actionPayload f5RuleAction

	if ! redirect {
		actionPayload = f5RuleAction{
			Name:    "0",
			Forward: true,
			Pool:    fmt.Sprintf("%s/%s", f5.partitionPath, poolname),
			Request: true,
			Select:  true,
			Vlan:    0,
		}
	} else {
		actionPayload = f5RuleAction{
			Name:    "0",
			HttpReply: true,
			Location: "tcl:https://[HTTP::host][HTTP::uri]",
		}
	}

	glog.Infof("Adding/updating action %s of rule %s in policy %s...", actionPayload.Name, policyname, routename)
	err = f5.post(actionUrl, actionPayload, nil)
	if err != nil {
		// Note: Seems that a HTTP conflict does not happen if the Action already exists, at least for the non-redirect case.
		glog.Warningf("Failed to add/update action: %s", err.Error())
		return err
	}

	success = true

	glog.V(4).Infof("Reading routes for policy %s.", policyname)
	routes, err := f5.getRoutes(policyname)
	if err != nil {
		glog.Warningf("Failed to get routes: %s", err.Error())
		return err
	}

	routes[routename] = true

	return nil
}

// AddInsecureRoute adds an F5 profile rule for the specified insecure route to F5
// BIG-IP, so that requests to the specified hostname and pathname will be
// routed to the specified pool.
func (f5 *f5LTM) AddInsecureRoute(routename, poolname, hostname, pathname string) error {
	return f5.addRoute(httpPolicyName, routename, poolname, hostname, pathname, false)
}

// AddInsecureRoute adds an F5 profile rule for the specified redirect route to F5
// BIG-IP, so that requests to the specified hostname and pathname will be
// redirect to HTTPS.
func (f5 *f5LTM) AddInsecureRedirectRoute(routename, poolname, hostname, pathname string) error {
	return f5.addRoute(httpPolicyName, routename, poolname, hostname, pathname, true)
}

// AddSecureRoute adds an F5 profile rule for the specified secure route to F5
// BIG-IP, so that requests to the specified hostname and pathname will be
// routed to the specified pool.
func (f5 *f5LTM) AddSecureRoute(routename, poolname, hostname, pathname string) error {
	return f5.addRoute(httpsPolicyName, routename, poolname, hostname, pathname, false)
}

// getReencryptRoutes returns f5.reencryptRoutes, first initializing it from
// F5 if it is zero.
func (f5 *f5LTM) getReencryptRoutes() (map[string]reencryptRoute, error) {
	routes := f5.reencryptRoutes
	if routes != nil {
		return routes, nil
	}

	hostsUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, f5.iControlUriResourceId(reencryptHostsDataGroupName))

	hostsRes := f5Datagroup{}

	err := f5.get(hostsUrl, &hostsRes)
	if err != nil {
		return nil, err
	}

	routesUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, f5.iControlUriResourceId(reencryptRoutesDataGroupName))

	routesRes := f5Datagroup{}

	err = f5.get(routesUrl, &routesRes)
	if err != nil {
		return nil, err
	}

	hosts := map[string]string{}

	for _, hostRecord := range hostsRes.Records {
		hosts[hostRecord.Key] = hostRecord.Value
	}

	f5.reencryptRoutes = map[string]reencryptRoute{}

	for _, routeRecord := range routesRes.Records {
		routename := routeRecord.Key
		hostname := routeRecord.Value

		poolname, foundPoolname := hosts[hostname]
		if ! foundPoolname {
			glog.Warningf("" +
				"%s datagroup maps route %s to hostname %s," +
				" but %s datagroup does not have an entry for that hostname" +
				" to map it to a pool.  Dropping route %s from datagroup %s...",
				reencryptRoutesDataGroupName,
				routename,
				hostname,
				reencryptHostsDataGroupName,
				routename,
				reencryptRoutesDataGroupName,
			)
			continue
		}

		f5.reencryptRoutes[routename] = reencryptRoute{
			hostname: hostname,
			poolname: poolname,
		}
	}

	return f5.reencryptRoutes, nil
}

// Updates the datagroups for reencrypt routes using the internal object's state.
func (f5 *f5LTM) updateReencryptRoutes() error {
	routes, err := f5.getReencryptRoutes()
	if err != nil {
		return err
	}

	// It would be *super* great if we could use CRUD operations on data-groups as
	// we do on pools, rules, and profiles, but we cannot: each data-group is
	// represented in JSON as an array, so we must PATCH the array in its
	// entirety.

	hostsRecords := []f5DatagroupRecord{}
	routesRecords := []f5DatagroupRecord{}
	for routename, route := range routes {
		hostsRecords = append(hostsRecords, f5DatagroupRecord{Key: route.hostname, Value: route.poolname})
		routesRecords = append(routesRecords, f5DatagroupRecord{Key: routename, Value: route.hostname})
	}

	hostsDatagroupUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, f5.iControlUriResourceId(reencryptHostsDataGroupName))

	hostsDatagroupPayload := f5Datagroup{
		Records: hostsRecords,
	}

	glog.Infof("Updating data-group %s.", reencryptHostsDataGroupName)
	err = f5.patch(hostsDatagroupUrl, hostsDatagroupPayload, nil)
	if err != nil {
		return err
	}

	glog.V(4).Infof("Datagroup %s updated.", reencryptHostsDataGroupName)

	routesDatagroupUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, f5.iControlUriResourceId(reencryptRoutesDataGroupName))

	routesDatagroupPayload := f5Datagroup{
		Records: routesRecords,
	}

	glog.Infof("Updating data-group %s.", reencryptRoutesDataGroupName)
	err = f5.patch(routesDatagroupUrl, routesDatagroupPayload, nil)
	if err != nil {
		return err
	}

	glog.V(4).Infof("Datagroup %s updated.", reencryptRoutesDataGroupName)

	return nil
}

// Returns f5.passthroughRoutes, first initializing it from BIG-IP if it is empty.
func (f5 *f5LTM) getPassthroughRoutes() (map[string]passthroughRoute, error) {
	routes := f5.passthroughRoutes
	if routes != nil {
		return routes, nil
	}

	hostsUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, f5.iControlUriResourceId(passthroughHostsDataGroupName))

	hostsRes := f5Datagroup{}

	err := f5.get(hostsUrl, &hostsRes)
	if err != nil {
		return nil, err
	}

	routesUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, f5.iControlUriResourceId(passthroughRoutesDataGroupName))

	routesRes := f5Datagroup{}

	err = f5.get(routesUrl, &routesRes)
	if err != nil {
		return nil, err
	}

	hosts := map[string]string{}

	for _, hostRecord := range hostsRes.Records {
		hosts[hostRecord.Key] = hostRecord.Value
	}

	f5.passthroughRoutes = map[string]passthroughRoute{}

	for _, routeRecord := range routesRes.Records {
		routename := routeRecord.Key
		hostname := routeRecord.Value

		poolname, foundPoolname := hosts[hostname]
		if ! foundPoolname {
			glog.Warningf("" +
				"%s datagroup maps route %s to hostname %s," +
				" but %s datagroup does not have an entry for that hostname" +
				" to map it to a pool.  Dropping route %s from datagroup %s...",
				passthroughRoutesDataGroupName,
				routename,
				hostname,
				passthroughHostsDataGroupName,
				routename,
				passthroughRoutesDataGroupName,
			)
			continue
		}

		f5.passthroughRoutes[routename] = passthroughRoute{
			hostname: hostname,
			poolname: poolname,
		}
	}

	return f5.passthroughRoutes, nil
}

// Updates the datagroups for passthrough routes using the internal object's state.
func (f5 *f5LTM) updatePassthroughRoutes() error {
	routes, err := f5.getPassthroughRoutes()
	if err != nil {
		return err
	}

	// It would be *super* great if we could use CRUD operations on data-groups as
	// we do on pools, rules, and profiles, but we cannot: each data-group is
	// represented in JSON as an array, so we must PATCH the array in its
	// entirety.

	hostsRecords := []f5DatagroupRecord{}
	routesRecords := []f5DatagroupRecord{}
	for routename, route := range routes {
		hostsRecords = append(hostsRecords, f5DatagroupRecord{Key: route.hostname, Value: route.poolname})
		routesRecords = append(routesRecords, f5DatagroupRecord{Key: routename, Value: route.hostname})
	}

	hostsDatagroupUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, f5.iControlUriResourceId(passthroughHostsDataGroupName))

	hostsDatagroupPayload := f5Datagroup{
		Records: hostsRecords,
	}

	glog.Infof("Updating data-group %s.", passthroughHostsDataGroupName)
	err = f5.patch(hostsDatagroupUrl, hostsDatagroupPayload, nil)
	if err != nil {
		return err
	}

	glog.V(4).Infof("Datagroup %s updated.", passthroughHostsDataGroupName)

	routesDatagroupUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/data-group/internal/%s", f5.host, f5.iControlUriResourceId(passthroughRoutesDataGroupName))

	routesDatagroupPayload := f5Datagroup{
		Records: routesRecords,
	}

	glog.Infof("Updating data-group %s.", passthroughRoutesDataGroupName)
	err = f5.patch(routesDatagroupUrl, routesDatagroupPayload, nil)
	if err != nil {
		return err
	}

	glog.V(4).Infof("Datagroup %s updated.", passthroughRoutesDataGroupName)

	return nil
}

// Adds the required datagroup records for the specified reeencrypt route,
// so that requests to the specified hostname will be routed to the specified pool through the iRule (which iRule?  SSL bridging is via the LTM policy?)
func (f5 *f5LTM) AddReencryptRoute(routename, poolname, hostname string) error {
	routes, err := f5.getReencryptRoutes()
	if err != nil {
		return err
	}

	routes[routename] = reencryptRoute{hostname: hostname, poolname: poolname}

	return f5.updateReencryptRoutes()
}

// AddPassthroughRoute adds the required datagroup records for the specified
// passthrough route to F5 BIG-IP, so that requests to the specified hostname
// will be routed to the specified pool.
func (f5 *f5LTM) AddPassthroughRoute(routename, poolname, hostname string) error {
	glog.Warningf("All BIG-IP features bypassed for route %s; TCP streams forwarded directly from world to pod.", passthroughHostsDataGroupName)

	routes, err := f5.getPassthroughRoutes()
	if err != nil {
		return err
	}

	routes[routename] = passthroughRoute{hostname: hostname, poolname: poolname}

	return f5.updatePassthroughRoutes()
}

// DeleteReencryptRoute deletes the datagroup records for the specified reencrypt route from F5 BIG-IP.
func (f5 *f5LTM) DeleteReencryptRoute(routename string) error {
	routes, err := f5.getReencryptRoutes()
	if err != nil {
		return err
	}

	_, exists := routes[routename]
	if ! exists {
		return fmt.Errorf("Reencrypt route %s does not exist in cache.", routename)
	}

	delete(routes, routename)

	return f5.updateReencryptRoutes()
}

// DeletePassthroughRoute deletes the datagroup records for the specified passthrough route from F5 BIG-IP.
func (f5 *f5LTM) DeletePassthroughRoute(routename string) error {
	routes, err := f5.getPassthroughRoutes()
	if err != nil {
		return err
	}

	_, exists := routes[routename]
	if ! exists {
		return fmt.Errorf("Passthrough route %s does not exist in cache.", routename)
	}

	delete(routes, routename)

	return f5.updatePassthroughRoutes()
}

// deleteRoute deletes the policy rule for the given routename from the given policy.
func (f5 *f5LTM) deleteRoute(policyname, routename string) error {
	ruleUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/policy/%s/rules/%s", f5.host, f5.iControlUriResourceId(policyname), routename)

	glog.Infof("Deleting rule %s from policy %s.", routename, policyname)
	err := f5.delete(ruleUrl, nil)
	if err != nil {
		if ! isGone(err) {
			return err
		}
	}

	delete(f5.routes[policyname], routename)

	glog.V(4).Infof("Route %s deleted.", routename)

	return nil
}

// DeleteInsecureRoute deletes the policy rule for the given insecure route.
func (f5 *f5LTM) DeleteInsecureRoute(routename string) error {
	return f5.deleteRoute(httpPolicyName, routename)
}

// DeleteSecureRoute deletes the policy rule for the given secure route.
func (f5 *f5LTM) DeleteSecureRoute(routename string) error {
	return f5.deleteRoute(httpsPolicyName, routename)
}

// AddCert adds the provided TLS certificate and private key to F5 BIG-IP for
// client-side TLS (i.e., encryption between the client and F5 BIG-IP),
// configures a corresponding client-ssl SSL profile, and associates it with the
// HTTPS vserver.  If a destination certificate is provided, AddCert adds that
// for server-side TLS (i.e., encryption between F5 BIG-IP and the pod),
// configures a corresponding server-ssl SSL profile, and associates it too with
// the vserver.
//
// TODO: There is a field called "CA" in the OpenShift control panel.
//       Perhaps it is meant to contain the CA root certificate, or
//       perhaps it is meant to contain one or more intermediate certificates?
//
//       In case of intermediates, the field would map well to the "chain" field
//       of client-ssl profiles in BIG-IP.  The certificates could just be uploaded
//       as another certificate (unique name) and selected via the "chain" field
//       of the client-ssl profile.
//
//       In case of an actual CA certificate, why?  For DANE TLS purposes perhaps?
//
func (f5 *f5LTM) AddCert(routename, hostname, cert, privkey, destCACert string) error {
	var deleteServerSslProfile, deleteClientSslProfileFromVserver, deleteClientSslProfile, deletePrivateKey, deleteCert, deleteCACert bool

	success := false

	defer func() {
		if ! success {
			glog.Warningf("Undoing all created objects due to previous failures in AddCert()...")
			f5.deleteCertParts(
				routename,
				false,
				deleteServerSslProfile,
				deleteClientSslProfileFromVserver,
				deleteClientSslProfile,
				deletePrivateKey,
				deleteCert,
				deleteCACert,
			)
		}
	}()

	var err error

	certname := fmt.Sprintf("%s-https-cert", routename)
	glog.V(4).Infof("Uploading server (and intermediate, if present) certificate(s) %s for route %s...", certname, routename)
	err = f5.uploadCert(cert, certname)
	if err != nil {
		glog.Warningf("Failed to upload server and intermediate certificate %s for route %s: %s", certname, routename, err.Error())
		return err
	}
	deleteCert = true

	keyname := fmt.Sprintf("%s-https-key", routename)
	glog.V(4).Infof("Uploading key %s for route %s...", keyname, routename)
	err = f5.uploadKey(privkey, keyname)
	if err != nil {
		glog.Warningf("Failed to upload key %s for route %s: %s", keyname, routename, err.Error())
		return err
	}
	deletePrivateKey = true

	if (len(cert) > 0) && (len(privkey) > 0) {
		clientSslProfileName := fmt.Sprintf("%s-client-ssl-profile", routename)
		err = f5.createClientSslProfile(clientSslProfileName, hostname, certname, keyname)
		if err != nil {
			if isConflict(err) {
				glog.V(4).Infof("Client-ssl profile %s for route %s already exists, skipping.", clientSslProfileName, routename)
			} else {
				glog.Warningf("Failed to create client-ssl profile %s for route %s: %s", clientSslProfileName, routename, err.Error())
				return err
			}
		}
		deleteClientSslProfile = true

		err = f5.associateClientSslProfileWithVserver(clientSslProfileName, f5.httpsVserver)
		if err != nil {
			if isConflict(err) {
				glog.V(4).Infof("Client-ssl profile %s for route %s already attached to virtual server %s, skipping.", clientSslProfileName, routename, f5.httpsVserver)
			} else {
				glog.Warningf("Failed to attach client-ssl profile %s to virtual server %s for route %s: %s", clientSslProfileName, f5.httpsVserver, routename, err.Error())
				return err
			}
		}
		deleteClientSslProfileFromVserver = true
	}

	if destCACert != "" {
		cacertname := fmt.Sprintf("%s-https-cabundle", routename)
		glog.V(4).Infof("Uploading 'destination CA cert' %s for route %s", cacertname, routename)
		err = f5.uploadCert(destCACert, cacertname)
		if err != nil {
			glog.Warningf("Failed to upload 'destination ca cert' for route %s: %s", routename, err.Error())
			return err
		}
		deleteCACert = true

		serverSslProfileName := fmt.Sprintf("%s-server-ssl-profile", routename)
		err = f5.createServerSslProfile(serverSslProfileName, hostname, cacertname)
		if err != nil {
			if isConflict(err) {
				glog.V(4).Infof("Server-ssl profile %s for route %s already exists, skipping.", serverSslProfileName, routename)
			} else {
				glog.Warningf("Failed to create server-ssl profile %s for route %s: %s", serverSslProfileName, routename, err.Error())
				return err
			}
		}
		deleteServerSslProfile = true

		err = f5.associateServerSslProfileWithVserver(serverSslProfileName, f5.httpsVserver)
		if err != nil {
			if isConflict(err) {
				glog.V(4).Infof("Server-ssl profile %s for route %s already attached to virtual server %s, skipping.", serverSslProfileName, routename, f5.httpsVserver)
			} else {
				glog.Warningf("Failed to attach server-ssl profile %s to virtual server %s for route %s: %s", serverSslProfileName, f5.httpsVserver, routename, err.Error())
				return err
			}
		}
	}

	success = true

	return nil
}

// Uploads the given certificate to F5 BIG-IP and installs it so that it can be used.
func (f5 *f5LTM) uploadCert(cert, certname string) error {
	if len(cert) == 0 {
		glog.Warningf("Size of certficate %s is zero. Refusing to upload to F5 BIG-IP.", certname)
		glog.Warningf("For this route to work, ensure the client-ssl profile flagged default-sni has a wildcard certificate.")
		// Returning OK, under the assumption that the BIG-IP administrator is supposed to manually handle certificates for this route.
		return nil
	}
	certfileName := fmt.Sprintf("%s.crt", certname)
	glog.Infof("Copying certificate %s to BIG-IP.", certname)
	err := f5.upload(certfileName, []byte(cert), nil)
	if err != nil {
		glog.Errorf("Error copying certificate %s to BIG-IP:\n%s", certname, err.Error())
		return err
	}

	certfilePath := fmt.Sprintf("/var/config/rest/downloads/%s", certfileName)
	installCertCommandUrl := fmt.Sprintf("https://%s/mgmt/tm/sys/crypto/cert", f5.host)
	installCertCommandPayload := f5InstallCommandPayload{
		Command:  "install",
		Name:     certname,
		Filename: certfilePath,
		Partition:  f5.partitionPath,
	}
	glog.Infof("Installing certificate %s on BIG-IP.", certname)
	return f5.post(installCertCommandUrl, installCertCommandPayload, nil)
}

// Uploads the given private key to F5 BIG-IP and installs it so that it can be used.
func (f5 *f5LTM) uploadKey(privkey, keyname string) error {
	if len(privkey) == 0 {
		glog.Warningf("Size of key %s is zero. Refusing to upload to F5 BIG-IP.", keyname)
		// Returning OK, under the assumption that the BIG-IP administrator is supposed to manually handle certificates for this route.
		return nil
	}
	keyfileName := fmt.Sprintf("%s.key", keyname)
	glog.Infof("Copying key %s to BIG-IP...", keyname)
	err := f5.upload(keyfileName, []byte(privkey), nil)
	if err != nil {
		glog.Errorf("Error copying key %s to BIG-IP.", keyname)
		return err
	}

	keyfilePath := fmt.Sprintf("/var/config/rest/downloads/%s", keyfileName)
	installKeyCommandUrl := fmt.Sprintf("https://%s/mgmt/tm/sys/crypto/key", f5.host)
	installKeyCommandPayload := f5InstallCommandPayload{
		Command:  "install",
		Name:     keyname,
		Filename: keyfilePath,
		Partition:  f5.partitionPath,
	}
	glog.Infof("Installing key %s on BIG-IP...", keyname)
	return f5.post(installKeyCommandUrl, installKeyCommandPayload, nil)
}

// Create a clientssl profile with the given name and for the specified hostname, certificate, and key.
func (f5 *f5LTM) createClientSslProfile(profilename, hostname, certname, keyname string) error {
	clientSslProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/profile/client-ssl", f5.host)

	clientSslProfilePayload := f5SslProfilePayload{
		// Although we do not specify extensions when installing the certificate and
		// private key, we *must* specify the extensions when referencing the
		// certificate in *this* request, or else F5 gets confused and returns
		// a misleading error message ("Client SSL profile must have RSA
		// certificate/key pair.").
		Certificate: fmt.Sprintf("%s.crt", certname),
		Key:         fmt.Sprintf("%s.key", keyname),
		Name:        profilename,
		Partition:   f5.partitionPath,
		ServerName:  hostname,
		DefaultsFrom: path.Join(f5.partitionPath, clientSslTemplateProfileName),
	}

	glog.Infof("Creating client-ssl profile %s.", profilename)
	return f5.post(clientSslProfileUrl, clientSslProfilePayload, nil)
}

// Create a serverssl profile with the given name and for the specified hostname and CA certificate.
func (f5 *f5LTM) createServerSslProfile(profilename, hostname, cacertname string) error {
	serverSslProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/profile/server-ssl", f5.host)

	serverSslProfilePayload := f5SslProfilePayload{
		// Similar as for createClientSslProfile, we must add an extension when
		// referencing the CA certificate here.
		Partition:         f5.partitionPath,
		Name:              profilename,
		DefaultsFrom:      path.Join(f5.partitionPath, serverSslTemplateProfileName),
		ServerName:        hostname,
		AuthenticateName:  hostname,
		PeerCertMode:      "require",
		CaFile:            fmt.Sprintf("%s.crt", cacertname),
	}
	glog.Infof("Creating server-ssl profile %s.", profilename)
	return f5.post(serverSslProfileUrl, serverSslProfilePayload, nil)
}

// Associates the specified clientssl profile with the specified virtual server.
func (f5 *f5LTM) associateClientSslProfileWithVserver(profilename, vservername string) error {
	vserverProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/virtual/%s/profiles", f5.host, f5.iControlUriResourceId(vservername))

	vserverProfilePayload := f5VserverProfilePayload{
		Name:    path.Join(f5.partitionPath, profilename),
		Context: "clientside",
	}

	glog.Infof("Associating client-ssl profile %s with virtual server %s.", profilename, vservername)
	return f5.post(vserverProfileUrl, vserverProfilePayload, nil)
}

// Associates the specified serverssl profile with the specified vserver in F5 BIG-IP.
func (f5 *f5LTM) associateServerSslProfileWithVserver(profilename, vservername string) error {
	vserverProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/virtual/%s/profiles", f5.host, f5.iControlUriResourceId(vservername))

	vserverProfilePayload := f5VserverProfilePayload{
		Name:    path.Join(f5.partitionPath, profilename),
		Context: "serverside",
	}

	glog.Infof("Associating server-ssl profile %s with virtual server %s.", profilename, vservername)
	return f5.post(vserverProfileUrl, vserverProfilePayload, nil)
}

// Deletes the TLS certificate and key for the specified route, as well as any related client-ssl or server-ssl profile.
func (f5 *f5LTM) DeleteCert(routename string) error {
	return f5.deleteCertParts(routename, true, true, true, true, true, true, true)
}

// Deletes the TLS-related configuration items from F5 BIG-IP, as specified by the Boolean arguments.
func (f5 *f5LTM) deleteCertParts(
	routename string,
	deleteServerSslProfileFromVserver,
	deleteServerSslProfile,
	deleteClientSslProfileFromVserver,
	deleteClientSslProfile,
	deletePrivateKey,
	deleteCert,
	deleteCACert bool,
) error {
	if deleteServerSslProfileFromVserver {
		serverSslProfileName := fmt.Sprintf("%s-server-ssl-profile", routename)
		serverSslVserverProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/virtual/%s/profiles/%s", f5.host, f5.iControlUriResourceId(f5.httpsVserver), serverSslProfileName)
		glog.Infof("Detaching server-ssl profile %s from virtual server %s.", serverSslProfileName, f5.httpsVserver)
		err := f5.delete(serverSslVserverProfileUrl, nil)
		if err != nil {
			if isGone(err) {
				glog.V(4).Infof("Skipping detaching server-ssl profile for route %s from virtual server %s because it does not exist", routename, f5.httpsVserver)
			} else {
				glog.V(4).Infof("Error detaching server-ssl profile for route %s from virtual server %s: %v", routename, f5.httpsVserver, err)
				return err
			}
		}
	}

	if deleteServerSslProfile {
		serverSslProfileName := fmt.Sprintf("%s-server-ssl-profile", routename)
		serverSslProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/profile/server-ssl/%s", f5.host, f5.iControlUriResourceId(serverSslProfileName))
		glog.Infof("Deleting server-ssl profile %s.", serverSslProfileName)
		err := f5.delete(serverSslProfileUrl, nil)
		if err != nil {
			if isGone(err) {
				glog.V(4).Infof("Skipping deletion of server-ssl profile for route %s because it does not exist", routename)
			} else {
				glog.V(4).Infof("Error deleting server-ssl profile for route %s: %v", routename, err)
				return err
			}
		}
	}

	if deleteClientSslProfileFromVserver {
		clientSslProfileName := fmt.Sprintf("%s-client-ssl-profile", routename)
		clientSslVserverProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/virtual/%s/profiles/%s", f5.host, f5.iControlUriResourceId(f5.httpsVserver), clientSslProfileName)
		glog.Infof("Detaching client-ssl profile %s from virtual server %s.", clientSslProfileName, f5.httpsVserver)
		err := f5.delete(clientSslVserverProfileUrl, nil)
		if err != nil {
			if isGone(err) {
				glog.V(4).Infof("Skipping detaching client-ssl profile for route %s from virtual server %s because it does not exist", routename, f5.httpsVserver)
			} else {
				glog.V(4).Infof("Error detaching client-ssl profile for route %s from virtual server %s: %v", routename, f5.httpsVserver, err)
				return err
			}
		}
	}

	if deleteClientSslProfile {
		clientSslProfileName := fmt.Sprintf("%s-client-ssl-profile", routename)
		clientSslProfileUrl := fmt.Sprintf("https://%s/mgmt/tm/ltm/profile/client-ssl/%s", f5.host, f5.iControlUriResourceId(clientSslProfileName))
		glog.Infof("Deleting client-ssl profile %s.", clientSslProfileName)
		err := f5.delete(clientSslProfileUrl, nil)
		if err != nil {
			if isGone(err) {
				glog.V(4).Infof("Skipping deletion of client-ssl profile for route %s because it does not exist", routename)
			} else {
				glog.V(4).Infof("Error deleting client-ssl profile for route %s: %v", routename, err)
				return err
			}
		}
	}

	if deletePrivateKey {
		keyname := fmt.Sprintf("%s-https-key", routename)
		keyUrl := fmt.Sprintf("https://%s/mgmt/tm/sys/file/ssl-key/%s", f5.host, f5.iControlUriResourceId(keyname + ".key"))
		glog.Infof("Uninstalling private key %s.", keyname)
		err := f5.delete(keyUrl, nil)
		if err != nil {
			if isGone(err) {
				glog.V(4).Infof("Skipping uninstall of private key for route %s because it does not exist", routename)
			} else {
				glog.V(4).Infof("Error uninstalling private key for route %s: %v", routename, err)
			}
		}
	}

	if deleteCert {
		certname := fmt.Sprintf("%s-https-cert", routename)
		certUrl := fmt.Sprintf("https://%s/mgmt/tm/sys/file/ssl-cert/%s", f5.host, f5.iControlUriResourceId(certname + ".crt"))
		glog.Infof("Uninstalling server certificate %s.", certname)
		err := f5.delete(certUrl, nil)
		if err != nil {
			if isGone(err) {
				glog.V(4).Infof("Skipping uninstall of server certificate for route %s because it does not exist", routename)
			} else {
				glog.V(4).Infof("Error uninstalling server certificate for route %s: %v", routename, err)
				return err
			}
		}
	}

	if deleteCACert {
		cacertname := fmt.Sprintf("%s-https-cabundle", routename)
		cacertUrl := fmt.Sprintf("https://%s/mgmt/tm/sys/file/ssl-cert/%s", f5.host, f5.iControlUriResourceId(cacertname + ".crt"))
		glog.Infof("Uninstalling CA certificate bundle %s.", cacertname)
		err := f5.delete(cacertUrl, nil)
		if err != nil {
			if isGone(err) {
				glog.V(4).Infof("Skipping uninstall of CA certificate bundle for route %s because it does not exist", routename)
			} else {
				glog.V(4).Infof("Error uninstalling CA certificate bundle for route %s: %v", routename, err)
				return err
			}
		}
	}

	return nil
}
