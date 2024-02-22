package tokens

import (
	"context"
	"net/url"
	"slices"

	"github.com/gophercloud/gophercloud/v2"
)

type ScopeDomain struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ScopeProject struct {
	ID     string       `json:"id,omitempty"`
	Name   string       `json:"name,omitempty"`
	Domain *ScopeDomain `json:"domain"`
}

type ScopeSystem struct {
	All bool `json:"all"`
}

type ScopeTrust struct {
	ID string `json:"id"`
}

// Scope allows a created token to be limited to a specific domain or project.
type Scope struct {
	Project *ScopeProject `json:"project,omitempty"`
	Domain  *ScopeDomain  `json:"domain,omitempty"`
	System  *ScopeSystem  `json:"system,omitempty"`
	Trust   *ScopeTrust   `json:"OS-TRUST:trust"`
}

type UserDomain struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type UserPassword struct {
	ID       string      `json:"id,omitempty"`
	Name     string      `json:"name,omitempty"`
	Domain   *UserDomain `json:"domain,omitempty"`
	Password string      `json:"password"`
}

type PasswordIdentity struct {
	User *UserPassword `json:"user"`
}

type TokenIdentity struct {
	ID string `json:"id"`
}

type UserTOTP struct {
	ID       string      `json:"id,omitempty"`
	Name     string      `json:"name,omitempty"`
	Domain   *UserDomain `json:"domain,omitempty"`
	Passcode string      `json:"password"`
}

type TOTPIdentity struct {
	User *UserTOTP `json:"user"`
}

type UserApplicationCredential struct {
	ID     string      `json:"id,omitempty"`
	Name   string      `json:"name,omitempty"`
	Domain *UserDomain `json:"domain,omitempty"`
}

type ApplicationCredentialIdentity struct {
	ID     string                     `json:"id,omitempty"`
	Name   string                     `json:"name,omitempty"`
	Secret string                     `json:"secret"`
	User   *UserApplicationCredential `json:"user"`
}

type OAuth1Identity struct {
	ConsumerKey string    `json:"-"`
	ConsumerSecret string `json:"-"`
	AccessKey string      `json:"-"`
	AccessSecret string   `json:"-"`
}

type Identity struct {
	Methods               []string                       `json:"methods"`
	Password              *PasswordIdentity              `json:"password"`
	Token                 *TokenIdentity                 `json:"token"`
	TOTP                  *TOTPIdentity                  `json:"totp"`
	ApplicationCredential *ApplicationCredentialIdentity `json:"application_credential"`
}

type CreateOptsBuilder interface {
	ToTokenCreateMap() (map[string]interface{}, error)
	ToTokenHeadersMap(client *gophercloud.ServiceClient) (map[string]string, error)
}

// CreateOpts contains options for creating a Token. This object is passed to
// the tokens.Create function. For more information about these parameters,
// see the Token object.
type CreateOpts struct {
	// Scope determines the scoping of the authentication request.
	Scope *Scope `json:"scope"`
	// Identity contains the credentials and information about the provider
	// being used.
	Identity *Identity `json:"identity"`
}

// ToTokenCreateMap allows CreateOptions to satisfy the AuthOptionsBuilder
// interface
func (opts *CreateOpts) ToTokenCreateMap() (map[string]interface{}, error) {
	return gophercloud.BuildRequestBody(opts, "auth")
}

// ToTokenHeadersMap allows CreateOptions to satisfy the AuthOptionsBuilder
// interface
func (opts *CreateOpts) ToTokenHeadersMap(client *gophercloud.ServiceClient) (map[string]string, error) {
	headerOpts := map[string]string{}
	if opts.Identity != nil && slices.Contains(opts.Identity.Methods, "v3oauth1") {
		q, err := buildOAuth1QueryString(opts, opts.OAuthTimestamp, "")
		if err != nil {
			return nil, err
		}
		stringToSign := buildOAuthStringToSign("POST", tokenURL(client), q.Query())
		signatureKeys := []string{opts.OAuthConsumerSecret, opts.OAuthTokenSecret}
		signature := url.QueryEscape(signString(opts.OAuthSignatureMethod, stringToSign, signatureKeys))
		authHeader := buildOAuthAuthorizationHeader(q.Query(), signature)

		headerOpts["X-Auth-Token"] = ""
		headerOpts["Authorization"] = authHeader(client)
	}
	// TODO: Handle oauth
	return nil, nil
}

func FromAuthOptions(ao gophercloud.AuthOptionsV3) (*CreateOpts, error) {
	if ao.AuthType == "" {
		if ao.TokenID != "" {
			ao.AuthType = "v3token"
		} else if ao.Password != "" {
			ao.AuthType = "v3password"
		} else if ao.Passcode != "" {
			ao.AuthType = "v3passcode"
		}
	}

	var identity *Identity
	var err error
	switch ao.AuthType {
	case "v3token":
		identity, err = getIdentityFromAuthOptionsToken(ao)
	case "v3password":
		identity, err = getIdentityFromAuthOptionsPassword(ao)
	case "v3totp":
		identity, err = getIdentityFromAuthOptionsTOTP(ao)
	case "v3applicationcredential":
		identity, err = getIdentityFromAuthOptionsApplicationCredential(ao)
	default:
		// TODO: error
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	var scope *Scope
	scope, err = getScopeFromAuthOptions(ao)
	if err != nil {
		return nil, err
	}

	return &CreateOpts{
		Identity: identity,
		Scope:    scope,
	}, nil
}

func getIdentityFromAuthOptionsToken(opts gophercloud.AuthOptionsV3) (*Identity, error) {
	return &Identity{
		Token: &TokenIdentity{
			ID: opts.TokenID,
		},
	}, nil
}

func getIdentityFromAuthOptionsPassword(opts gophercloud.AuthOptionsV3) (*Identity, error) {
	// At least one of Username and UserID must be specified.
	if opts.Username == "" && opts.UserID == "" {
		return nil, gophercloud.ErrUsernameOrUserID{}
	}

	// If Username is provided, UserID may not be provided.
	if opts.Username != "" && opts.UserID != "" {
		return nil, gophercloud.ErrUsernameOrUserID{}
	}

	if opts.Username != "" {
		// Either UserDomainID or UserDomainName must also be specified.
		if opts.UserDomainID == "" && opts.UserDomainName == "" {
			return nil, gophercloud.ErrDomainIDOrDomainName{}
		}

		// If UserDomainName is provided, UserDomainID may not be provided.
		if opts.UserDomainName != "" && opts.UserDomainID != "" {
			return nil, gophercloud.ErrDomainIDOrDomainName{}
		}

		var domain *UserDomain
		if opts.UserDomainID != "" {
			// Configure the request for Username and Password authentication
			// with a UserDomainID.
			domain = &UserDomain{
				ID: opts.UserDomainID,
			}
		} else { // opts.UserDomainName
			// Configure the request for Username and Password authentication
			// with a UserDomainName.
			domain = &UserDomain{
				Name: opts.UserDomainName,
			}
		}

		return &Identity{
			Password: &PasswordIdentity{
				User: &UserPassword{
					Name:     opts.Username,
					Domain:   domain,
					Password: opts.Password,
				},
			},
		}, nil
	} else { // opts.UserID != ""
		// If UserID is specified, neither UserDomainID nor UserDomainName may be.
		if opts.UserDomainID != "" {
			return nil, gophercloud.ErrDomainIDWithUserID{}
		}
		if opts.UserDomainName != "" {
			return nil, gophercloud.ErrDomainNameWithUserID{}
		}

		// Configure the request for Username and Password authentication
		// with a UserDomainName.
		// Configure the request for UserID and Password authentication.
		return &Identity{
			Password: &PasswordIdentity{
				User: &UserPassword{
					ID:       opts.UserID,
					Password: opts.Password,
				},
			},
		}, nil
	}
}

func getIdentityFromAuthOptionsTOTP(opts gophercloud.AuthOptionsV3) (*Identity, error) {
	// At least one of Username and UserID must be specified.
	if opts.Username == "" && opts.UserID == "" {
		return nil, gophercloud.ErrUsernameOrUserID{}
	}

	if opts.Username != "" {
		// If Username is provided, UserID may not be provided.
		if opts.UserID != "" {
			return nil, gophercloud.ErrUsernameOrUserID{}
		}

		// Either UserDomainID or UserDomainName must also be specified...
		if opts.UserDomainID == "" && opts.UserDomainName == "" {
			return nil, gophercloud.ErrDomainIDOrDomainName{}
		}

		// ...but not both.
		if opts.UserDomainID != "" && opts.UserDomainName != "" {
			return nil, gophercloud.ErrDomainIDOrDomainName{}
		}

		var domain *UserDomain
		if opts.UserDomainID != "" {
			// Configure the request for Username and Password authentication
			// with a UserDomainID.
			domain = &UserDomain{
				ID: opts.UserDomainID,
			}
		} else { // opts.UserDomainName
			// Configure the request for Username and Password authentication
			// with a UserDomainName.
			domain = &UserDomain{
				Name: opts.UserDomainName,
			}
		}

		return &Identity{
			TOTP: &TOTPIdentity{
				User: &UserTOTP{
					Name:     opts.Username,
					Domain:   domain,
					Passcode: opts.Passcode,
				},
			},
		}, nil
	} else { // opts.UserID != ""
		// If UserID is specified, neither UserDomainID nor UserDomainName may
		// be.
		if opts.UserDomainID != "" {
			return nil, gophercloud.ErrDomainIDWithUserID{}
		}
		if opts.UserDomainName != "" {
			return nil, gophercloud.ErrDomainNameWithUserID{}
		}

		return &Identity{
			TOTP: &TOTPIdentity{
				User: &UserTOTP{
					ID:       opts.UserID,
					Passcode: opts.Passcode,
				},
			},
		}, nil
	}
}

func getIdentityFromAuthOptionsApplicationCredential(opts gophercloud.AuthOptionsV3) (*Identity, error) {
	// If Username is provided, UserID may not be provided.
	if opts.ApplicationCredentialID == "" && opts.ApplicationCredentialName == "" {
		return nil, gophercloud.ErrAppCredIDOrAppCredName{}
	}

	if opts.ApplicationCredentialSecret == "" {
		return nil, gophercloud.ErrAppCredMissingSecret{}
	}

	if opts.ApplicationCredentialID != "" {
		// Configure the request for ApplicationCredentialID authentication.
		// https://github.com/openstack/keystoneauth/blob/stable/rocky/keystoneauth1/identity/v3/application_credential.py#L48-L67
		// There are three kinds of possible application_credential requests
		// 1. application_credential id + secret
		// 2. application_credential name + secret + user_id
		// 3. application_credential name + secret + username + domain_id / domain_name
		return &Identity{
			ApplicationCredential: &ApplicationCredentialIdentity{
				ID:     opts.ApplicationCredentialID,
				Secret: opts.ApplicationCredentialSecret,
			},
		}, nil
	} else { // opts.ApplicationCredentialName != ""
		// If Username is provided, UserID may not be provided.
		if opts.Username != "" && opts.UserID != "" {
			return nil, gophercloud.ErrUsernameOrUserID{}
		}

		var user *UserApplicationCredential

		if opts.UserID != "" {
			// UserID could be used without the domain information
			user = &UserApplicationCredential{
				ID: opts.UserID,
			}
		} else { // Username != ""
			// Make sure that UserDomainID or UserDomainName are provided among
			// Username
			if opts.UserDomainID == "" && opts.UserDomainName == "" {
				return nil, gophercloud.ErrDomainIDOrDomainName{}
			}

			if opts.UserDomainID != "" && opts.UserDomainName != "" {
				return nil, gophercloud.ErrDomainIDOrDomainName{}
			}

			domain := &UserDomain{}

			if opts.UserDomainID != "" {
				domain.ID = opts.UserDomainID
			} else { // opts.UserDomainName != ""
				domain.Name = opts.UserDomainName
			}

			user = &UserApplicationCredential{
				Name:   opts.Username,
				Domain: domain,
			}
		}

		return &Identity{
			ApplicationCredential: &ApplicationCredentialIdentity{
				Name:   opts.ApplicationCredentialName,
				Secret: opts.ApplicationCredentialSecret,
				User:   user,
			},
		}, nil
	}
}

func getScopeFromAuthOptions(opts gophercloud.AuthOptionsV3) (*Scope, error) {
	if opts.SystemScope != "" { // system-scoped
		if opts.SystemScope != "all" {
			// TODO: error
		}

		return &Scope{
			System: &ScopeSystem{
				All: true,
			},
		}, nil
	} else if opts.TrustID != "" {
		return &Scope{
			Trust: &ScopeTrust{
				ID: opts.TrustID,
			},
		}, nil
	} else if opts.ProjectName != "" { // project-scoped (via name)
		// ProjectName provided: either DomainID or DomainName must also be supplied.
		if opts.DomainID == "" && opts.DomainName == "" {
			return nil, gophercloud.ErrScopeDomainIDOrDomainName{}
		}

		// ProjectID may not be supplied.
		if opts.ProjectID != "" {
			return nil, gophercloud.ErrScopeProjectIDOrProjectName{}
		}

		var domain *ScopeDomain
		if opts.DomainID != "" {
			domain = &ScopeDomain{
				ID: opts.DomainID,
			}
		} else { // opts.Scope.DomainName != ""
			domain = &ScopeDomain{
				Name: opts.DomainName,
			}
		}

		return &Scope{
			Project: &ScopeProject{
				Name:   opts.ProjectName,
				Domain: domain,
			},
		}, nil
	} else if opts.ProjectID != "" { // project-scoped (via ID)
		// ProjectID provided. ProjectName, DomainID, and DomainName may not be provided.
		if opts.DomainID != "" {
			return nil, gophercloud.ErrScopeProjectIDAlone{}
		}
		if opts.DomainName != "" {
			return nil, gophercloud.ErrScopeProjectIDAlone{}
		}

		return &Scope{
			Project: &ScopeProject{
				ID: opts.ProjectID,
			},
		}, nil
	} else if opts.DomainName != "" {
		// DomainName provided. DomainID may not be provided.
		if opts.DomainID != "" {
			return nil, gophercloud.ErrScopeDomainIDOrDomainName{}
		}

		return &Scope{
			Domain: &ScopeDomain{
				ID: opts.DomainID,
			},
		}, nil
	} else if opts.DomainID != "" { // domain-scoped (via name)
		// DomainID provided. DomainName may not be provided.
		if opts.DomainName != "" {
			return nil, gophercloud.ErrScopeDomainIDOrDomainName{}
		}

		return &Scope{
			Domain: &ScopeDomain{
				ID: opts.DomainID,
			},
		}, nil
	}

	return nil, nil
}

func subjectTokenHeaders(subjectToken string) map[string]string {
	return map[string]string{
		"X-Subject-Token": subjectToken,
	}
}

// Create authenticates and either generates a new token, or changes the Scope
// of an existing token.
func Create(ctx context.Context, c *gophercloud.ServiceClient, opts CreateOpts) (r CreateResult) {
	b, err := opts.ToTokenCreateMap()
	if err != nil {
		r.Err = err
		return
	}
	h, err := opts.ToTokenHeadersMap(c)
	if err != nil {
		r.Err = err
		return
	}
	resp, err := c.Post(ctx, tokenURL(c), b, &r.Body, &gophercloud.RequestOpts{
		OmitHeaders: []string{"X-Auth-Token"},
		MoreHeaders: h,
	})
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	return
}

// Get validates and retrieves information about another token.
func Get(ctx context.Context, c *gophercloud.ServiceClient, token string) (r GetResult) {
	resp, err := c.Get(ctx, tokenURL(c), &r.Body, &gophercloud.RequestOpts{
		MoreHeaders: subjectTokenHeaders(token),
		OkCodes:     []int{200, 203},
	})
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	return
}

// Validate determines if a specified token is valid or not.
func Validate(ctx context.Context, c *gophercloud.ServiceClient, token string) (bool, error) {
	resp, err := c.Head(ctx, tokenURL(c), &gophercloud.RequestOpts{
		MoreHeaders: subjectTokenHeaders(token),
		OkCodes:     []int{200, 204, 404},
	})
	if err != nil {
		return false, err
	}

	return resp.StatusCode == 200 || resp.StatusCode == 204, nil
}

// Revoke immediately makes specified token invalid.
func Revoke(ctx context.Context, c *gophercloud.ServiceClient, token string) (r RevokeResult) {
	resp, err := c.Delete(ctx, tokenURL(c), &gophercloud.RequestOpts{
		MoreHeaders: subjectTokenHeaders(token),
	})
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	return
}
