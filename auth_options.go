package gophercloud

import "time"

type AuthOptions interface {
	GetIdentityEndpoint() string
	IsScoped() bool
	CanReauth() bool
}

/*
AuthOptionsV2 stores information needed to authenticate to an OpenStack Cloud
using the Identity v2 API. You can populate one manually, or use a provider's
AuthOptionsFromEnv() function to read relevant information from the standard
environment variables. Pass one to a provider's AuthenticatedClient function to
authenticate and obtain a ProviderClient representing an active session on that
provider.

Its fields are the union of those recognized by each identity implementation and
provider.

An example of manually providing authentication information:

	opts := gophercloud.AuthOptionsV2{
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
type AuthOptionsV2 struct {
	// IdentityEndpoint specifies the HTTP endpoint that is required to work with
	// the Identity API of the appropriate version. While it's ultimately needed by
	// all of the identity services, it will often be populated by a provider-level
	// function.
	//
	// The IdentityEndpoint is typically referred to as the "auth_url" or
	// "OS_AUTH_URL" in the information provided by the cloud operator.
	IdentityEndpoint string

	// The TenantID and TenantName fields are optional for the Identity V2 API.
	TenantID   string
	TenantName string

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

	// Username is required if using Identity V2 API. Consult with your provider's
	// control panel to discover your account's username. In Identity V3, either
	// UserID or a combination of Username and DomainID or DomainName are needed.
	Username string
	UserID   string
	Password string
	TokenID  string
}

func (ao AuthOptionsV2) GetIdentityEndpoint() string {
	return ao.IdentityEndpoint
}

func (ao AuthOptionsV2) IsScoped() bool {
	return false
}

func (ao AuthOptionsV2) CanReauth() bool {
	return false
}

// Type SignatureMethod is a OAuth1 SignatureMethod type.
type OAuthSignatureMethod string

const (
	// HMACSHA1 is a recommended OAuth1 signature method.
	HMACSHA1 OAuthSignatureMethod = "HMAC-SHA1"

	// PLAINTEXT signature method is not recommended to be used in
	// production environment.
	PLAINTEXT OAuthSignatureMethod = "PLAINTEXT"
)

/*
AuthOptionsV3 stores information needed to authenticate to an OpenStack Cloud
using the Identity v3 API. You can populate one manually, or use a provider's
AuthOptionsFromEnv() function to read relevant information from the standard
environment variables. Pass one to a provider's AuthenticatedClient function to
authenticate and obtain a ProviderClient representing an active session on that
provider.

Its fields are the union of those recognized by each identity implementation and
provider.

An example of manually providing authentication information:

	opts := gophercloud.AuthOptionsV3{
		IdentityEndpoint: "https://openstack.example.com:5000/v3",
		Username: "{username}",
		Password: "{password}",
		ProjectID: "{project_id}",
	}

	provider, err := openstack.AuthenticatedClient(opts)

An example of using AuthOptionsFromEnv(), where the environment variables can
be read from a file, such as a standard openrc file:

	opts, err := openstack.AuthOptionsFromEnv()
	provider, err := openstack.AuthenticatedClient(opts)
*/
type AuthOptionsV3 struct {
	// IdentityEndpoint specifies the HTTP endpoint that is required to work with
	// the Identity API of the appropriate version. While it's ultimately needed by
	// all of the identity services, it will often be populated by a provider-level
	// function.
	//
	// The IdentityEndpoint is typically referred to as the "auth_url" or
	// "OS_AUTH_URL" in the information provided by the cloud operator.
	IdentityEndpoint string

	// AuthType indicates the authentication backend to use. Currently the
	// following are supported:
	//
	// v3password,v3token,v3totp,v3applicationcredential,v3oauth1
	AuthType string

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

	// At most one of DomainID or DomainName must be provided if attempting
	// domain-scoped operations. Otherwise, both are optional.
	DomainID   string
	DomainName string

	// At most one of ProjectDomainID or ProjectDomainName must be provided if
	// using ProjectName. Otherwise, both are optional.
	ProjectDomainID   string
	ProjectDomainName string

	// At most one of ProjectID or ProjectName must be provided if attempting
	// project-scoped operations. Otherwise, both are optional.
	ProjectID   string
	ProjectName string

	// Scope indicates whether to use system scope. The only valid value is
	// "all".
	SystemScope string

	// TrustID indicates that trust that should be used when making requests.
	TrustID string

	// At most one of UserDomainID or UserDomainName must be provided if using
	// Username. Otherwise, both are optional.
	UserDomainID   string
	UserDomainName string

	// At most one of Username or UserID must be provided if using password
	// authentication (v3password), TOTP authentication (v3totp) or application
	// credential authentication (v3applicationcredential) using an application
	// credential name, along with the relevant secret field for the method
	Username string
	UserID   string

	// Password must be specified if using password authentication (v3password)
	Password string

	// Passcode must be specified if using TOTP authentication (v3totp)
	Passcode string

	// TokenID must be specified if using token authentication (v3token)
	TokenID string

	// At most one of ApplicationCredentialID or ApplicationCredentialName must
	// be provided if using application credential authentication
	// (v3applicationcredential), along with the secret
	ApplicationCredentialID     string
	ApplicationCredentialName   string
	ApplicationCredentialSecret string

	// OAuthConsumerKey is the OAuth1 Consumer Key.
	OAuthConsumerKey string

	// OAuthConsumerSecret is the OAuth1 Consumer Secret. Used to generate
	// an OAuth1 request signature.
	OAuthConsumerSecret string

	// OAuthToken is the OAuth1 Request Token.
	OAuthToken string

	// OAuthTokenSecret is the OAuth1 Request Token Secret. Used to generate
	// an OAuth1 request signature.
	OAuthTokenSecret string

	// OAuthSignatureMethod is the OAuth1 signature method the Consumer used
	// to sign the request. Supported values are "HMAC-SHA1" or "PLAINTEXT".
	// "PLAINTEXT" is not recommended for production usage.
	OAuthSignatureMethod OAuthSignatureMethod

	// OAuthTimestamp is an OAuth1 request timestamp. If nil, current Unix
	// timestamp will be used.
	OAuthTimestamp *time.Time

	// OAuthNonce is an OAuth1 request nonce. Nonce must be a random string,
	// uniquely generated for each request. Will be generated automatically
	// when it is not set.
	OAuthNonce string
}

func (ao AuthOptionsV3) GetIdentityEndpoint() string {
	return ao.IdentityEndpoint
}

func (ao AuthOptionsV3) IsScoped() bool {
	return (ao.SystemScope != "" || ao.DomainID != "" || ao.DomainName != "" || ao.ProjectID != "" || ao.ProjectName != "")
}

func (ao AuthOptionsV3) CanReauth() bool {
	return ao.AuthType != "v3token"
}
