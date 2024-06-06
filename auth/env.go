package auth

import (
	"os"
	"strings"

	"github.com/gophercloud/gophercloud/v2"
)

func AuthOptionsFromEnv() (AuthOptionsBuilder, error) {
	if os.Getenv("OS_IDENTITY_API_VERSION") == "2.0" {
		return AuthOptionsFromEnvV2()
	} else {
		return AuthOptionsFromEnvV3()
	}
}

func AuthOptionsFromEnvV2() (*AuthOptionsV2, error) {
	// TODO: Consider making use of struct tags rather than defining this all manually
	authURL := os.Getenv("OS_AUTH_URL")
	authType := "" // v2 doesn't have the concept of auth types: this is purely for consistency

	tenantName := os.Getenv("OS_TENANT_NAME")
	tenantID := os.Getenv("OS_TENANT_ID")

	username := os.Getenv("OS_USERNAME")
	password := os.Getenv("OS_PASSWORD")
	token := os.Getenv("OS_TOKEN")

	if password != "" {
		authType = "v2password"
	} else {
		authType = "v2token"
	}

	var opts AuthV2Mechanism

	switch authType {
	case "v2password":
		opts = V2PasswordOpts{
			Username:   username,
			Password:   password,
			TenantID:   tenantID,
			TenantName: tenantName,
		}
	case "v2token":
		opts = V2TokenOpts{
			Token:      token,
			TenantID:   tenantID,
			TenantName: tenantName,
		}
	default:
		return nil, gophercloud.ErrUnsupportedAuthType{AuthType: authType}
	}

	ao := &AuthOptionsV2{
		AuthURL: authURL,
		Auth:    opts,
	}

	return ao, nil
}

func AuthOptionsFromEnvV3() (AuthOptionsBuilder, error) {
	// TODO: Consider making use of struct tags rather than defining this all manually
	authURL := os.Getenv("OS_AUTH_URL")
	authType := os.Getenv("OS_AUTH_TYPE")
	authMethods := strings.Split(os.Getenv("OS_AUTH_METHODS"), ",")

	if authURL == "" {
		return nil, gophercloud.ErrMissingEnvironmentVariable{
			EnvironmentVariable: "OS_AUTH_URL",
		}
	}

	// If the user didn't provide an explicit auth type, try to guess
	if authType == "" {
		password := os.Getenv("OS_PASSWORD")
		passcode := os.Getenv("OS_PASSCODE")
		applicationCredentialID := os.Getenv("OS_APPLICATION_CREDENTIAL_ID")
		applicationCredentialName := os.Getenv("OS_APPLICATION_CREDENTIAL_NAME")
		token := os.Getenv("OS_TOKEN")

		if password != "" {
			authType = "v3password"
		} else if passcode != "" {
			authType = "v3totp"
		} else if token != "" {
			authType = "v3token"
		} else if applicationCredentialID != "" || applicationCredentialName != "" {
			authType = "v3applicationcredential"
		}
	}

	scope := &Scope{
		DomainID:    os.Getenv("OS_DOMAIN_ID"),
		DomainName:  os.Getenv("OS_DOMAIN_NAME"),
		ProjectID:   os.Getenv("OS_PROJECT_ID"),
		ProjectName: os.Getenv("OS_PROJECT_NAME"),
	}

	var opts AuthV3Mechanism

	switch authType {
	case "v3password":
		opts = V3PasswordOpts{
			Username:       os.Getenv("OS_USERNAME"),
			UserID:         os.Getenv("OS_USERID"),
			Password:       os.Getenv("OS_PASSWORD"),
			UserDomainID:   os.Getenv("OS_USER_DOMAIN_ID"),
			UserDomainName: os.Getenv("OS_USER_DOMAIN_NAME"),
			Scope:          scope,
		}
	case "v3totp":
		opts = V3TOTPOpts{
			Username:       os.Getenv("OS_USERNAME"),
			UserID:         os.Getenv("OS_USERID"),
			Passcode:       os.Getenv("OS_PASSCODE"),
			UserDomainID:   os.Getenv("OS_USER_DOMAIN_ID"),
			UserDomainName: os.Getenv("OS_USER_DOMAIN_NAME"),
			Scope:          scope,
		}
	case "v3applicationcredential":
		opts = V3ApplicationCredentialOpts{
			Username:                    os.Getenv("OS_USERNAME"),
			UserID:                      os.Getenv("OS_USERID"),
			ApplicationCredentialID:     os.Getenv("OS_APPLICATION_CREDENTIAL_ID"),
			ApplicationCredentialName:   os.Getenv("OS_APPLICATION_CREDENTIAL_NAME"),
			ApplicationCredentialSecret: os.Getenv("OS_APPLICATION_CREDENTIAL_SECRET"),
			UserDomainID:                os.Getenv("OS_USER_DOMAIN_ID"),
			UserDomainName:              os.Getenv("OS_USER_DOMAIN_NAME"),
			Scope:                       scope,
		}
	case "v3token":
		opts = V3TokenOpts{
			Token: os.Getenv("OS_TOKEN"),
			Scope: scope,
		}
	case "v3multifactor":
	default:
		return nil, gophercloud.ErrUnsupportedAuthType{AuthType: authType}
	}

	ao := &AuthOptionsV3{
		AuthURL:     authURL,
		AuthType:    authType,
		AuthMethods: authMethods,
		Auth:        opts,
	}

	return ao, nil
}
