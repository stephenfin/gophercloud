package gophercloud

import (
	"context"
)

// AuthOptionsBuilder provides the ability for extensions to add additional
// parameters to AuthOptions. Extensions must satisfy all required methods.
type AuthOptionsBuilder interface {
	Authenticate(ctx context.Context, client *ServiceClient) error
	CanReauth() bool
}

/*
AuthOptions stores information needed to authenticate to an OpenStack Cloud.
You can populate one manually, or use a provider's AuthOptionsFromEnv() function
to read relevant information from the standard environment variables. Pass one
to a provider's AuthenticatedClient function to authenticate and obtain a
ProviderClient representing an active session on that provider.

Its fields are the union of those recognized by each identity implementation and
provider.

An example of manually providing authentication information:

	opts := gophercloud.AuthOptions{
	  IdentityEndpoint: "https://openstack.example.com:5000/v2.0",
	  Username: "{username}",
	  Password: "{password}",
	  TenantID: "{tenant_id}",
	}

	provider, err := openstack.AuthenticatedClient(context.TODO(), opts)

An example of using AuthOptionsFromEnv(), where the environment variables can
be read from a file, such as a standard openrc file:

	opts, err := openstack.AuthOptionsFromEnv()
	provider, err := openstack.AuthenticatedClient(context.TODO(), opts)
*/
type AuthOptions struct {
	// IdentityEndpoint specifies the HTTP endpoint that is required to work with
	// the Identity API of the appropriate version. While it's ultimately needed by
	// all of the identity services, it will often be populated by a provider-level
	// function.
	//
	// The IdentityEndpoint is typically referred to as the "auth_url" or
	// "OS_AUTH_URL" in the information provided by the cloud operator.
	IdentityEndpoint string

	// AuthType is the authentication type. This should correspond to the name
	// of a plugin from keystoneauth. Only a select set of auth types is
	// currently supported by gophercloud.
	AuthType string

	// AuthMethods is the authentication method. This will be automatically
	// populated based on AuthType and is usually only necessary to specify
	// when using multifactor auth. Only a select set of auth types is
	// currently supported by gophercloud.
	AuthMethods []string

	// Username is required if using Identity V2 API. Consult with your provider's
	// control panel to discover your account's username. In Identity V3, either
	// UserID or a combination of Username and DomainID or DomainName are needed.
	Username string
	UserID   string

	Password string

	// Passcode is used in TOTP authentication method
	Passcode string

	// At most one of DomainID and DomainName must be provided if using Username
	// with Identity V3. Otherwise, either are optional.
	DomainID   string
	DomainName string

	// The TenantID and TenantName fields are optional for the Identity V2 API.
	// The same fields are known as project_id and project_name in the Identity
	// V3 API, but are collected as TenantID and TenantName here in both cases.
	// Some providers allow you to specify a TenantName instead of the TenantId.
	// Some require both. Your provider's authentication policies will determine
	// how these fields influence authentication.
	// If DomainID or DomainName are provided, they will also apply to TenantName.
	// It is not currently possible to authenticate with Username and a Domain
	// and scope to a Project in a different Domain by using TenantName. To
	// accomplish that, the ProjectID will need to be provided as the TenantID
	// option.
	TenantID   string
	TenantName string

	// TokenID allows users to authenticate (possibly as another user) with an
	// authentication token ID.
	TokenID string

	// Scope determines the scoping of the authentication request.
	Scope *AuthScope

	// Authentication through Application Credentials requires supplying name, project and secret
	// For project we can use TenantID
	ApplicationCredentialID     string
	ApplicationCredentialName   string
	ApplicationCredentialSecret string

	// v3oauth1 parameters
	OAuthConsumerKey    string
	OAuthConsumerSecret string
	OAuthToken          string
	OAuthTokenSecret    string

	// Meta parameters

	// AllowReauth should be set to true if you grant permission for Gophercloud to
	// cache your credentials in memory, and to allow Gophercloud to attempt to
	// re-authenticate automatically if/when your token expires.  If you set it to
	// false, it will not cache these settings, but re-authentication will not be
	// possible.  This setting defaults to false.
	//
	// NOTE: The reauth function will try to re-authenticate endlessly if left
	// unchecked. The way to limit the number of attempts is to provide a custom
	// HTTP client to the provider client and provide a transport that implements
	// the RoundTripper interface and stores the number of failed retries. For an
	// example of this, see here:
	// https://github.com/rackspace/rack/blob/1.0.0/auth/clients.go#L311
	AllowReauth bool
}

// AuthScope allows a created token to be limited to a specific domain or project.
type AuthScope struct {
	ProjectID   string
	ProjectName string
	DomainID    string
	DomainName  string
	System      bool
	TrustID     string
}

// Authenticate allows AuthOptions to satisfy the AuthOptionsBuilder interface.
// It's a no-op and is never called since AuthOptions is special-cased.
func (opts AuthOptions) Authenticate(context.Context, *ServiceClient) error {
	return nil
}

func (opts AuthOptions) CanReauth() bool {
	if opts.Passcode != "" {
		// cannot reauth using TOTP passcode
		return false
	}

	return opts.AllowReauth
}
