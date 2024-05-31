package tokens

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/common"
)

type ScopeDomain struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ScopeProject struct {
	ID     string       `json:"id,omitempty"`
	Name   string       `json:"name,omitempty"`
	Domain *ScopeDomain `json:"domain,omitempty"`
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
	Trust   *ScopeTrust   `json:"OS-TRUST:trust,omitempty"`
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
	Passcode string      `json:"passcode"`
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
	User   *UserApplicationCredential `json:"user,omitempty"`
}

type OAuth1Identity struct{}

type Identity struct {
	Methods               []string                       `json:"methods"`
	Password              *PasswordIdentity              `json:"password,omitempty"`
	Token                 *TokenIdentity                 `json:"token,omitempty"`
	TOTP                  *TOTPIdentity                  `json:"totp,omitempty"`
	ApplicationCredential *ApplicationCredentialIdentity `json:"application_credential,omitempty"`
	OAuth1                *OAuth1Identity                `json:"oauth1,omitempty"`
}

// CreateOpts contains options for creating a Token. This object is passed to
// the tokens.Create function. For more information about these parameters,
// see the Token object.
type CreateOpts struct {
	// Scope determines the scoping of the authentication request.
	Scope *Scope `json:"scope,omitempty"`
	// Identity contains the credentials and information about the provider.
	// being used.
	Identity *Identity `json:"identity"`
	// Authorization is the standard Authorization header, which is used for
	// some authentication mechanisms (e.g. OAuth1)
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
	Authorization string `h:"Authorization" json:"-"`

	// AllowReauth indicates whether these options can be used to allow reauth.
	AllowReauth bool `json:"-"`
}

// CreateOptsBuilder allows extensions to add additional paramters to token
// create requests.
type CreateOptsBuilder interface {
	ToTokenCreateMap() (map[string]any, error)
	ToTokenHeadersMap(c *gophercloud.ServiceClient) (map[string]string, error)
}

// nolint:unparam
func getIdentityFromAuthOptionsToken(opts gophercloud.AuthOptions) (*Identity, error) {
	// Because we aren't using password authentication, it's an error to also
	// provide any of the user-based authentication parameters
	if opts.UserID != "" {
		return nil, gophercloud.ErrUserIDWithToken{}
	}
	if opts.Username != "" {
		return nil, gophercloud.ErrUsernameWithToken{}
	}
	if opts.DomainID != "" {
		return nil, gophercloud.ErrDomainIDWithToken{}
	}
	if opts.DomainName != "" {
		return nil, gophercloud.ErrDomainNameWithToken{}
	}

	return &Identity{
		Methods: []string{"token"},
		Token: &TokenIdentity{
			ID: opts.TokenID,
		},
	}, nil
}

func getIdentityFromAuthOptionsPassword(opts gophercloud.AuthOptions) (*Identity, error) {
	// At least one of Username and UserID must be specified.
	if opts.Username == "" && opts.UserID == "" {
		return nil, gophercloud.ErrUsernameOrUserID{}
	}

	// If Username is provided, UserID may not be provided.
	if opts.Username != "" && opts.UserID != "" {
		return nil, gophercloud.ErrUsernameOrUserID{}
	}

	if opts.Password == "" {
		return nil, gophercloud.ErrMissingPassword{}
	}

	if opts.Username != "" {
		// TODO: We need to expose UserDomainName and UserDomainID via AuthOptions
		// Either UserDomainID or UserDomainName must also be specified.
		if opts.DomainID == "" && opts.DomainName == "" {
			return nil, gophercloud.ErrDomainIDOrDomainName{}
		}

		// If UserDomainName is provided, UserDomainID may not be provided.
		if opts.DomainName != "" && opts.DomainID != "" {
			return nil, gophercloud.ErrDomainIDOrDomainName{}
		}

		var domain *UserDomain
		if opts.DomainID != "" {
			// Configure the request for Username and Password authentication
			// with a UserDomainID.
			domain = &UserDomain{
				ID: opts.DomainID,
			}
		} else { // opts.DomainName
			// Configure the request for Username and Password authentication
			// with a UserDomainName.
			domain = &UserDomain{
				Name: opts.DomainName,
			}
		}

		return &Identity{
			Methods: []string{"password"},
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
		if opts.DomainID != "" {
			return nil, gophercloud.ErrDomainIDWithUserID{}
		}
		if opts.DomainName != "" {
			return nil, gophercloud.ErrDomainNameWithUserID{}
		}

		// Configure the request for Username and Password authentication
		// with a UserDomainName.
		// Configure the request for UserID and Password authentication.
		return &Identity{
			Methods: []string{"password"},
			Password: &PasswordIdentity{
				User: &UserPassword{
					ID:       opts.UserID,
					Password: opts.Password,
				},
			},
		}, nil
	}
}

func getIdentityFromAuthOptionsTOTP(opts gophercloud.AuthOptions) (*Identity, error) {
	// At least one of Username and UserID must be specified.
	if opts.Username == "" && opts.UserID == "" {
		return nil, gophercloud.ErrUsernameOrUserID{}
	}

	// If Username is provided, UserID may not be provided.
	if opts.Username != "" && opts.UserID != "" {
		return nil, gophercloud.ErrUsernameOrUserID{}
	}

	if opts.Username != "" {
		// TODO: We need to expose UserDomainName and UserDomainID via AuthOptions
		// Either UserDomainID or UserDomainName must also be specified...
		if opts.DomainID == "" && opts.DomainName == "" {
			return nil, gophercloud.ErrDomainIDOrDomainName{}
		}

		// ...but not both.
		if opts.DomainID != "" && opts.DomainName != "" {
			return nil, gophercloud.ErrDomainIDOrDomainName{}
		}

		var domain *UserDomain
		if opts.DomainID != "" {
			// Configure the request for Username and Password authentication
			// with a UserDomainID.
			domain = &UserDomain{
				ID: opts.DomainID,
			}
		} else { // opts.UserDomainName
			// Configure the request for Username and Password authentication
			// with a UserDomainName.
			domain = &UserDomain{
				Name: opts.DomainName,
			}
		}

		return &Identity{
			Methods: []string{"totp"},
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
		if opts.DomainID != "" {
			return nil, gophercloud.ErrDomainIDWithUserID{}
		}
		if opts.DomainName != "" {
			return nil, gophercloud.ErrDomainNameWithUserID{}
		}

		return &Identity{
			Methods: []string{"totp"},
			TOTP: &TOTPIdentity{
				User: &UserTOTP{
					ID:       opts.UserID,
					Passcode: opts.Passcode,
				},
			},
		}, nil
	}
}

func getIdentityFromAuthOptionsApplicationCredential(opts gophercloud.AuthOptions) (*Identity, error) {
	// At least one of ID or Name must be provided.
	if opts.ApplicationCredentialID == "" && opts.ApplicationCredentialName == "" {
		return nil, gophercloud.ErrAppCredIDOrAppCredName{}
	}

	// If ID is provided, Name may not be provided.
	if opts.ApplicationCredentialID != "" && opts.ApplicationCredentialName != "" {
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
			Methods: []string{"application_credential"},
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
			// TODO: We need to expose UserDomainName and UserDomainID via AuthOptions
			// Make sure that UserDomainID or UserDomainName are provided among
			// Username
			if opts.DomainID == "" && opts.DomainName == "" {
				return nil, gophercloud.ErrDomainIDOrDomainName{}
			}

			if opts.DomainID != "" && opts.DomainName != "" {
				return nil, gophercloud.ErrDomainIDOrDomainName{}
			}

			domain := &UserDomain{}

			if opts.DomainID != "" {
				domain.ID = opts.DomainID
			} else { // opts.UserDomainName != ""
				domain.Name = opts.DomainName
			}

			user = &UserApplicationCredential{
				Name:   opts.Username,
				Domain: domain,
			}
		}

		return &Identity{
			Methods: []string{"application_credential"},
			ApplicationCredential: &ApplicationCredentialIdentity{
				Name:   opts.ApplicationCredentialName,
				Secret: opts.ApplicationCredentialSecret,
				User:   user,
			},
		}, nil
	}
}

// nolint:unparam
func getIdentityFromAuthOptionsOAuth1(opts gophercloud.AuthOptions) (*Identity, error) {
	return &Identity{
		Methods: []string{"oauth1"},
		OAuth1:  &OAuth1Identity{},
	}, nil
}

func getIdentityFromAuthOptionsMultifactor(opts gophercloud.AuthOptions) (*Identity, error) {
	identity := &Identity{
		Methods: []string{},
	}
	var err error

	authMethods := opts.AuthMethods
	if len(authMethods) == 0 {
		authMethods = []string{"password", "totp"}
	}

	for _, authMethod := range authMethods {
		var sub *Identity
		switch authMethod {
		case "password":
			sub, err = getIdentityFromAuthOptionsPassword(opts)
			if err != nil {
				return nil, err
			}
			identity.Password = sub.Password
		case "totp":
			sub, err = getIdentityFromAuthOptionsTOTP(opts)
			if err != nil {
				return nil, err
			}
			identity.TOTP = sub.TOTP
		default:
			return nil, fmt.Errorf("unsupported auth method")
		}
		if err != nil {
			return nil, err
		}

		identity.Methods = append(identity.Methods, sub.Methods[0])
	}
	return identity, nil
}

func getScopeFromAuthOptions(opts gophercloud.AuthOptions) (*Scope, error) {
	if opts.Scope == nil {
		if opts.TenantID != "" { // project-scoped (via fallback ID)
			// TenantID provided. TenantName, DomainID, and DomainName may not be provided.
			if opts.TenantName != "" {
				return nil, gophercloud.ErrScopeProjectIDAlone{}
			}
			if opts.DomainID != "" {
				return nil, gophercloud.ErrScopeProjectIDAlone{}
			}
			if opts.DomainName != "" {
				return nil, gophercloud.ErrScopeProjectIDAlone{}
			}

			return &Scope{
				Project: &ScopeProject{
					ID: opts.TenantID,
				},
			}, nil
		} else if opts.TenantName != "" { // project-scoped (via fallback name)
			// ProjectName provided: either DomainID or DomainName must also be supplied.
			if opts.DomainID == "" && opts.DomainName == "" {
				return nil, gophercloud.ErrScopeDomainIDOrDomainName{}
			}

			// ProjectID may not be supplied.
			if opts.TenantID != "" {
				return nil, gophercloud.ErrScopeProjectIDOrProjectName{}
			}

			var domain *ScopeDomain
			if opts.DomainID != "" {
				domain = &ScopeDomain{
					ID: opts.DomainID,
				}
			} else { // opts.DomainName != ""
				domain = &ScopeDomain{
					Name: opts.DomainName,
				}
			}

			return &Scope{
				Project: &ScopeProject{
					Name:   opts.TenantName,
					Domain: domain,
				},
			}, nil
		}
		return nil, nil
	}

	if opts.Scope.System { // system-scoped
		return &Scope{
			System: &ScopeSystem{
				All: true,
			},
		}, nil
	} else if opts.Scope.TrustID != "" {
		return &Scope{
			Trust: &ScopeTrust{
				ID: opts.Scope.TrustID,
			},
		}, nil
	} else if opts.Scope.ProjectName != "" { // project-scoped (via name)
		// ProjectName provided: either DomainID or DomainName must also be supplied.
		if opts.Scope.DomainID == "" && opts.Scope.DomainName == "" {
			return nil, gophercloud.ErrScopeDomainIDOrDomainName{}
		}

		// ProjectID may not be supplied.
		if opts.Scope.ProjectID != "" {
			return nil, gophercloud.ErrScopeProjectIDOrProjectName{}
		}

		var domain *ScopeDomain
		if opts.Scope.DomainID != "" {
			domain = &ScopeDomain{
				ID: opts.Scope.DomainID,
			}
		} else { // opts.Scope.DomainName != ""
			domain = &ScopeDomain{
				Name: opts.Scope.DomainName,
			}
		}

		return &Scope{
			Project: &ScopeProject{
				Name:   opts.Scope.ProjectName,
				Domain: domain,
			},
		}, nil
	} else if opts.Scope.ProjectID != "" { // project-scoped (via ID)
		// ProjectID provided. ProjectName, DomainID, and DomainName may not be provided.
		if opts.Scope.DomainID != "" {
			return nil, gophercloud.ErrScopeProjectIDAlone{}
		}
		if opts.Scope.DomainName != "" {
			return nil, gophercloud.ErrScopeProjectIDAlone{}
		}

		return &Scope{
			Project: &ScopeProject{
				ID: opts.Scope.ProjectID,
			},
		}, nil
	} else if opts.Scope.DomainName != "" {
		// DomainName provided. DomainID may not be provided.
		if opts.Scope.DomainID != "" {
			return nil, gophercloud.ErrScopeDomainIDOrDomainName{}
		}

		return &Scope{
			Domain: &ScopeDomain{
				Name: opts.Scope.DomainName,
			},
		}, nil
	} else if opts.Scope.DomainID != "" { // domain-scoped (via name)
		// DomainID provided. DomainName may not be provided.
		if opts.Scope.DomainName != "" {
			return nil, gophercloud.ErrScopeDomainIDOrDomainName{}
		}

		return &Scope{
			Domain: &ScopeDomain{
				ID: opts.Scope.DomainID,
			},
		}, nil
	}

	return nil, nil
}

func getAuthorizationHeaderFromAuthOptions(client *gophercloud.ServiceClient, authType string, opts gophercloud.AuthOptions) (string, error) {
	var authHeader string
	var err error

	switch authType {
	case "v3oauth1":
		oauthOptions := &common.OAuth1SignatureOptions{
			Token:       opts.OAuthToken,
			TokenSecret: opts.OAuthTokenSecret,
		}
		authHeader, err = common.BuildOAuth1AuthorizationHeader(opts.OAuthConsumerKey, opts.OAuthConsumerSecret, tokenURL(client), "POST", oauthOptions)
		if err != nil {
			return "", err
		}
	}

	return authHeader, nil
}

func (opts *CreateOpts) ToTokenCreateMap() (map[string]any, error) {
	b, err := gophercloud.BuildRequestBody(opts, "auth")
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (opts *CreateOpts) ToTokenHeadersMap(client *gophercloud.ServiceClient) (map[string]string, error) {
	h, err := gophercloud.BuildHeaders(opts)
	if err != nil {
		return nil, err
	}
	return h, err
}

// FromAuthOptions converts a gophercloud.AuthOptions object to a CreateOpts object
func FromAuthOptions(client *gophercloud.ServiceClient, opts gophercloud.AuthOptions) (*CreateOpts, error) {
	authType := opts.AuthType
	if authType == "" {
		if opts.TokenID != "" {
			authType = "v3token"
		} else if opts.Password != "" && opts.Passcode != "" {
			authType = "v3multifactor"
		} else if opts.Password != "" {
			authType = "v3password"
		} else if opts.Passcode != "" {
			authType = "v3totp"
		} else if opts.ApplicationCredentialSecret != "" {
			authType = "v3applicationcredential"
		} else {
			// We don't have enough information to continue.
			return nil, gophercloud.ErrMissingPassword{}
		}
	}

	var identity *Identity
	var err error
	switch authType {
	case "v3token":
		identity, err = getIdentityFromAuthOptionsToken(opts)
	case "v3password":
		identity, err = getIdentityFromAuthOptionsPassword(opts)
	case "v3totp":
		identity, err = getIdentityFromAuthOptionsTOTP(opts)
	case "v3applicationcredential":
		identity, err = getIdentityFromAuthOptionsApplicationCredential(opts)
	case "v3oauth1":
		identity, err = getIdentityFromAuthOptionsOAuth1(opts)
	case "v3multifactor":
		identity, err = getIdentityFromAuthOptionsMultifactor(opts)
	default:
		return nil, fmt.Errorf("unsupported auth method")
	}

	if err != nil {
		return nil, err
	}

	scope, err := getScopeFromAuthOptions(opts)
	if err != nil {
		return nil, err
	}

	authorization, err := getAuthorizationHeaderFromAuthOptions(client, authType, opts)
	if err != nil {
		return nil, err
	}

	createOpts := &CreateOpts{
		Identity:      identity,
		Scope:         scope,
		Authorization: authorization,
	}

	createOpts.AllowReauth = opts.AllowReauth

	return createOpts, nil
}

// Create authenticates and either generates a new token, or changes the Scope
// of an existing token.
func Create(ctx context.Context, c *gophercloud.ServiceClient, opts CreateOptsBuilder) (r CreateResult) {
	b, err := opts.ToTokenCreateMap()
	if err != nil {
		r.Err = err
		return
	}

	headers, err := opts.ToTokenHeadersMap(c)
	if err != nil {
		r.Err = err
		return
	}

	resp, err := c.Post(ctx, tokenURL(c), b, &r.Body, &gophercloud.RequestOpts{
		OmitHeaders: []string{"X-Auth-Token"},
		MoreHeaders: headers,
	})
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	return
}

func subjectTokenHeaders(subjectToken string) map[string]string {
	return map[string]string{
		"X-Subject-Token": subjectToken,
	}
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
