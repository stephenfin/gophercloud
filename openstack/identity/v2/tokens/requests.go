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
}

// ToTokenCreateMap allows CreateOptions to satisfy the AuthOptionsBuilder
// interface
func (opts CreateOpts) ToTokenCreateMap() (map[string]interface{}, error) {
	return gophercloud.BuildRequestBody(opts, "auth")
}

// ToTokenHeadersMap allows CreateOptions to satisfy the AuthOptionsBuilder
// interface
//
// This is a no-op since no v2 auth mechanism uses headers.
func (opts CreateOpts) ToTokenHeadersMap() (map[string]string, error) {
	return nil, nil
}

// TODO: Does this belong here?
func (opts CreateOpts) CanReauth() bool {
	return true
}

// Create will create a new Token based on the values in CreateOpts. To extract
// the Token object from the response, call the Extract method on the
// CreateResult.
//
// Generally, rather than interact with this call directly, end users should
// call openstack.AuthenticatedClient(), which abstracts all of the gory details
// about navigating service catalogs and such.
func Create(ctx context.Context, client *gophercloud.ServiceClient, opts gophercloud.AuthOptionsBuilder) (r CreateResult) {
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
func Get(ctx context.Context, client *gophercloud.ServiceClient, token string) (r GetResult) {
	resp, err := client.Get(ctx, GetURL(client, token), &r.Body, &gophercloud.RequestOpts{
		OkCodes: []int{200, 203},
	})
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	return
}
