package auth

import "github.com/gophercloud/gophercloud/v2"

type V3ApplicationCredentialOpts struct {
	Username                    string
	UserID                      string
	ApplicationCredentialID     string
	ApplicationCredentialName   string
	ApplicationCredentialSecret string
	UserDomainID                string
	UserDomainName              string
	Scope                       *Scope
}

func (opts V3ApplicationCredentialOpts) ToAuthBody() ([]string, map[string]map[string]any, error) {
	type domainReq struct {
		ID   *string `json:"id,omitempty"`
		Name *string `json:"name,omitempty"`
	}

	type userReq struct {
		ID     *string    `json:"id,omitempty"`
		Name   *string    `json:"name,omitempty"`
		Domain *domainReq `json:"domain,omitempty"`
	}

	type applicationCredentialReq struct {
		ID     string  `json:"id,omitempty"`
		Name   string  `json:"name,omitempty"`
		User   userReq `json:"user"`
		Secret string  `json:"secret"`
	}

	authMethods := []string{"applicationcredential"}

	req := applicationCredentialReq{
		User: userReq{},
	}

	// There are three kinds of possible application_credential requests
	//
	// 1. application_credential id + secret
	// 2. application_credential name + secret + user_id
	// 3. application_credential name + secret + username + domain_id / domain_name
	if opts.ApplicationCredentialSecret == "" {
		return authMethods, nil, gophercloud.ErrAppCredMissingSecret{}
	}

	// Exactly one of ApplicationCredentialID and ApplicationCredentialName must be specified
	if opts.ApplicationCredentialID == "" && opts.ApplicationCredentialName == "" {
		// TODO: Application credential-specific error
		return authMethods, nil, gophercloud.ErrUsernameOrUserID{}
	} else if opts.ApplicationCredentialID != "" && opts.ApplicationCredentialName != "" {
		return authMethods, nil, gophercloud.ErrUsernameOrUserID{}
	}

	req.ID = opts.ApplicationCredentialID
	req.Name = opts.ApplicationCredentialName
	req.Secret = opts.ApplicationCredentialSecret

	// Exactly one of Username and UserID must be specified
	if opts.Username == "" && opts.UserID == "" {
		return authMethods, nil, gophercloud.ErrUsernameOrUserID{}
	} else if opts.Username != "" && opts.UserID != "" {
		return authMethods, nil, gophercloud.ErrUsernameOrUserID{}
	}

	if opts.Username != "" {
		// Exactly one of DomainID or DomainName must be specified
		if opts.UserDomainID == "" && opts.UserDomainName == "" {
			return authMethods, nil, gophercloud.ErrDomainIDOrDomainName{}
		} else if opts.UserDomainID != "" && opts.UserDomainName != "" {
			return authMethods, nil, gophercloud.ErrDomainIDOrDomainName{}
		}

		var domain *domainReq

		if opts.UserDomainID != "" {
			domain = &domainReq{ID: &opts.UserDomainID}
		} else { // opts.DomainName != ""
			domain = &domainReq{Name: &opts.UserDomainName}
		}

		req.User.Name = &opts.Username
		req.User.Domain = domain
	} else { // opts.UserID != ""
		// None of DomainID or DomainName may be specified
		if opts.UserDomainID != "" {
			return authMethods, nil, gophercloud.ErrDomainIDWithUserID{}
		} else if opts.UserDomainName != "" {
			return authMethods, nil, gophercloud.ErrDomainNameWithUserID{}
		}
		req.User.ID = &opts.UserID
	}

	b, err := gophercloud.BuildRequestBody(req, "")
	if err != nil {
		return authMethods, nil, err
	}

	result := map[string]map[string]any{
		"applicationcredential": b,
	}

	return authMethods, result, nil
}

func (opts V3ApplicationCredentialOpts) ToAuthHeaders() (map[string]any, error) {
	return nil, nil
}

func (opts V3ApplicationCredentialOpts) CanReauth() bool {
	return true
}
