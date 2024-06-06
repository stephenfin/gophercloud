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

	username := os.Getenv("OS_USERNAME")
	password := os.Getenv("OS_PASSWORD")
	token := os.Getenv("OS_TOKEN")

	if username != "" && password != "" {
		authType = "v2password"
	} else if token != "" {
		authType = "v2token"
	}

	var opts AuthV2Mechanism

	switch authType {
	case "v2password":
	case "v2token":
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

	var opts AuthV3Mechanism

	switch authType {
	case "v3password":
	case "v3totp":
	case "v3applicationcredential":
	case "v3token":
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
