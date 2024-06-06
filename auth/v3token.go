package auth

import "github.com/gophercloud/gophercloud/v2"

type V3TokenOpts struct {
	Token string
	Scope *Scope
}

func (opts V3TokenOpts) ToAuthBody() ([]string, map[string]map[string]any, error) {
	type tokenReq struct {
		Token string `json:"token"`
	}

	authMethods := []string{"token"}
	req := tokenReq{
		Token: opts.Token,
	}

	b, err := gophercloud.BuildRequestBody(req, "")
	if err != nil {
		return authMethods, nil, err
	}

	result := map[string]map[string]any{
		"token": b,
	}

	return authMethods, result, nil
}

func (opts V3TokenOpts) ToAuthHeaders() (map[string]any, error) {
	return nil, nil
}

func (opts V3TokenOpts) CanReauth() bool {
	return false
}
