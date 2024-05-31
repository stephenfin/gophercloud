package tokens

import (
	"context"

	"github.com/gophercloud/gophercloud/v2"
)

// PasswordCredentials represents the required options to authenticate
// with a username and password.
type PasswordCredentials struct {
	Username string `json:"username" required:"true"`
	Password string `json:"password" required:"true"`
}

// TokenCredentials represents the required options to authenticate
// with a token.
type TokenCredentials struct {
	ID string `json:"id,omitempty" required:"true"`
}

// CreateOpts contains options for creating a Token. This object is passed to
// the tokens.Create function. For more information about these parameters,
// see the Token object.
type CreateOpts struct {
	// The TenantID and TenantName fields are optional for the Identity V2 API.
	// Some providers allow you to specify a TenantName instead of the TenantId.
	// Some require both. Your provider's authentication policies will determine
	// how these fields influence authentication.
	TenantID   string `json:"tenantId,omitempty"`
	TenantName string `json:"tenantName,omitempty"`

	// PasswordCredentials allows users to authenticate with a username and
	// password
	PasswordCredentials *PasswordCredentials `json:"passwordCredentials,omitempty" xor:"TokenCredentials"`

	// TokenCredentials allows users to authenticate (possibly as another user)
	// with an authentication token ID.
	TokenCredentials *TokenCredentials `json:"token,omitempty" xor:"PasswordCredentials"`

	// AllowReauth should be set to true if you grant permission for Gophercloud
	// to cache your credentials in memory, and to allow Gophercloud to attempt
	// to re-authenticate automatically if/when your token expires.  If you set
	// it to false, it will not cache these settings, but re-authentication will
	// not be possible.  This setting defaults to false.
	AllowReauth bool `json:"-"`
}

// CreateOptsBuilder allows extensions to add additional parameters to the
// token create request.
type CreateOptsBuilder interface {
	// ToTokenCreateMap assembles the Create request body, returning an error
	// if parameters are missing or inconsistent.
	ToTokenCreateMap() (map[string]any, error)
}

// ToTokenCreateMap builds a token request body from the given AuthOptions.
func (opts CreateOpts) ToTokenCreateMap() (map[string]any, error) {
	b, err := gophercloud.BuildRequestBody(opts, "auth")
	if err != nil {
		return nil, err
	}
	return b, nil
}

// FromAuthOptions converts an AuthOptions object to a CreateOpts object
func FromAuthOptions(client *gophercloud.ServiceClient, opts gophercloud.AuthOptions) (*CreateOpts, error) {
	createOpts := &CreateOpts{
		TenantID:   opts.TenantID,
		TenantName: opts.TenantName,
	}

	if opts.Password != "" {
		createOpts.PasswordCredentials = &PasswordCredentials{
			Username: opts.Username,
			Password: opts.Password,
		}
	} else {
		createOpts.TokenCredentials = &TokenCredentials{
			ID: opts.TokenID,
		}
	}

	createOpts.AllowReauth = opts.AllowReauth

	return createOpts, nil
}

// Create authenticates to the identity service and attempts to acquire a Token.
// Generally, rather than interact with this call directly, end users should
// call openstack.AuthenticatedClient(), which abstracts all of the gory details
// about navigating service catalogs and such.
func Create(ctx context.Context, client *gophercloud.ServiceClient, opts CreateOptsBuilder) (r CreateResult) {
	b, err := opts.ToTokenCreateMap()
	if err != nil {
		r.Err = err
		return
	}
	resp, err := client.Post(ctx, CreateURL(client), b, &r.Body, &gophercloud.RequestOpts{
		OkCodes:     []int{200, 203},
		OmitHeaders: []string{"X-Auth-Token"},
	})
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	return
}

// Get validates and retrieves information for user's token.
func Get(ctx context.Context, client *gophercloud.ServiceClient, id string) (r GetResult) {
	resp, err := client.Get(ctx, GetURL(client, id), &r.Body, &gophercloud.RequestOpts{
		OkCodes: []int{200, 203},
	})
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	return
}
