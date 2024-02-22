package noauth

import (
	"fmt"
	"strings"

	"github.com/gophercloud/gophercloud/v2"
)

// EndpointOpts specifies a "noauth" Cinder Endpoint.
type EndpointOpts struct {
	// CinderEndpoint [required] is currently only used with "noauth" Cinder.
	// A cinder endpoint with "auth_strategy=noauth" is necessary, for example:
	// http://example.com:8776/v2.
	CinderEndpoint string
}

// NewClient prepares an unauthenticated ProviderClient instance.
func NewClient(options gophercloud.AuthOptions) (*gophercloud.ProviderClient, error) {
	var username, projectName string

	switch v := options.(type) {
	case gophercloud.AuthOptionsV2:
	case gophercloud.AuthOptionsV3:
		username = v.Username
		projectName = v.ProjectName
		if username == "" {
			username = "admin"
		}
		if projectName == "" {
			projectName = "admin"
		}
	default:
		return nil, fmt.Errorf("Unsupported AuthOptions type")
	}

	client := &gophercloud.ProviderClient{
		TokenID: fmt.Sprintf("%s:%s", username, projectName),
	}

	return client, nil
}

func initClientOpts(client *gophercloud.ProviderClient, eo EndpointOpts, clientType string) (*gophercloud.ServiceClient, error) {
	sc := new(gophercloud.ServiceClient)
	if eo.CinderEndpoint == "" {
		return nil, fmt.Errorf("CinderEndpoint is required")
	}

	token := strings.Split(client.TokenID, ":")
	if len(token) != 2 {
		return nil, fmt.Errorf("Malformed noauth token")
	}

	endpoint := fmt.Sprintf("%s%s", gophercloud.NormalizeURL(eo.CinderEndpoint), token[1])
	sc.Endpoint = gophercloud.NormalizeURL(endpoint)
	sc.ProviderClient = client
	sc.Type = clientType
	return sc, nil
}

// NewBlockStorageNoAuthV2 creates a ServiceClient that may be used to access "noauth" v2 block storage service.
func NewBlockStorageNoAuthV2(client *gophercloud.ProviderClient, eo EndpointOpts) (*gophercloud.ServiceClient, error) {
	return initClientOpts(client, eo, "volumev2")
}

// NewBlockStorageNoAuthV3 creates a ServiceClient that may be used to access "noauth" v3 block storage service.
func NewBlockStorageNoAuthV3(client *gophercloud.ProviderClient, eo EndpointOpts) (*gophercloud.ServiceClient, error) {
	return initClientOpts(client, eo, "volumev3")
}
