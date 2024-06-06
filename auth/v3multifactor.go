package auth

import (
	"fmt"
	"maps"

	"github.com/gophercloud/gophercloud/v2"
)

type V3MultifactorOpts struct {
	AuthMethods []AuthV3Mechanism
	Scope       *Scope
}

func (opts V3MultifactorOpts) ToAuthBody() ([]string, map[string]map[string]any, error) {
	result := map[string]map[string]any{}
	authMethods := []string{}
	for _, authMethod := range opts.AuthMethods {
		var authResult map[string]map[string]any
		var err error

		switch authMethod.(type) {
		case V3PasswordOpts:
			authMethods = append(authMethods, "v3password")
		case V3TOTPOpts:
			authMethods = append(authMethods, "v3totp")
		case V3ApplicationCredentialOpts:
			authMethods = append(authMethods, "v3applicationcredential")
		case V3TokenOpts:
			authMethods = append(authMethods, "v3applicationcredential")
		default:
			return authMethods, nil, gophercloud.ErrUnsupportedAuthType{AuthType: fmt.Sprintf("%T", authMethod)}
		}

		_, authResult, err = authMethod.ToAuthBody()
		if err != nil {
			return authMethods, nil, err
		}

		maps.Copy(result, authResult)
	}

	return authMethods, result, nil
}

func (opts V3MultifactorOpts) ToAuthHeaders() (map[string]any, error) {
	return nil, nil
}

func (opts V3MultifactorOpts) CanReauth() bool {
	return false
}
