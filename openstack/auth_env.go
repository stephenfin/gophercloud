package openstack

import (
	"os"
	"strings"

	"github.com/gophercloud/gophercloud/v2"
)

func authOptionsFromEnvV2() (gophercloud.AuthOptions, error) {
	authURL := os.Getenv("OS_AUTH_URL")
	username := os.Getenv("OS_USERNAME")
	userID := os.Getenv("OS_USERID")
	token := os.Getenv("OS_TOKEN")
	password := os.Getenv("OS_PASSWORD")
	tenantID := os.Getenv("OS_TENANT_ID")
	tenantName := os.Getenv("OS_TENANT_NAME")

	ao := &gophercloud.AuthOptionsV2{
		IdentityEndpoint: authURL,
		TenantID:         tenantID,
		TenantName:       tenantName,
		Username:         username,
		UserID:           userID,
		Password:         password,
		TokenID:          token,
	}

	return ao, nil
}

func authOptionsFromEnvV3() (gophercloud.AuthOptions, error) {
	authURL := os.Getenv("OS_AUTH_URL")
	authType := os.Getenv("OS_AUTH_TYPE")
	authMethods := strings.Split(os.Getenv("OS_AUTH_TYPE"), ",")
	username := os.Getenv("OS_USERNAME")
	userID := os.Getenv("OS_USERID")
	password := os.Getenv("OS_PASSWORD")
	passcode := os.Getenv("OS_PASSCODE")
	projectID := os.Getenv("OS_PROJECT_ID")
	projectName := os.Getenv("OS_PROJECT_NAME")
	domainID := os.Getenv("OS_DOMAIN_ID")
	domainName := os.Getenv("OS_DOMAIN_NAME")
	userDomainID := os.Getenv("OS_USER_DOMAIN_ID")
	userDomainName := os.Getenv("OS_USER_DOMAIN_NAME")
	projectDomainID := os.Getenv("OS_PROJECT_DOMAIN_ID")
	projectDomainName := os.Getenv("OS_PROJECT_DOMAIN_NAME")
	applicationCredentialID := os.Getenv("OS_APPLICATION_CREDENTIAL_ID")
	applicationCredentialName := os.Getenv("OS_APPLICATION_CREDENTIAL_NAME")
	applicationCredentialSecret := os.Getenv("OS_APPLICATION_CREDENTIAL_SECRET")
	systemScope := os.Getenv("OS_SYSTEM_SCOPE")

	// If OS_PROJECT_ID is not set but OS_TENANT_ID is, fallback
	if projectID == "" {
		projectID = os.Getenv("OS_TENANT_ID")
	}

	// If OS_PROJECT_NAME is not set but OS_TENANT_NAME is, fallback
	if projectName == "" {
		projectName = os.Getenv("OS_TENANT_NAME")
	}

	if authURL == "" {
		err := gophercloud.ErrMissingEnvironmentVariable{
			EnvironmentVariable: "OS_AUTH_URL",
		}
		return nil, err
	}

	if authType == "" {
		authType = "v3password"
	}

	if len(authMethods) > 0 && authType != "v3multifactor" {
		// TODO: raise error about mismatch
	}

	if userID == "" && username == "" {
		// Empty username and userID could be ignored, when applicationCredentialID and applicationCredentialSecret are set
		if applicationCredentialID == "" && applicationCredentialSecret == "" {
			err := gophercloud.ErrMissingAnyoneOfEnvironmentVariables{
				EnvironmentVariables: []string{"OS_USERID", "OS_USERNAME"},
			}
			return nil, err
		}
	}

	if password == "" && passcode == "" && applicationCredentialID == "" && applicationCredentialName == "" {
		err := gophercloud.ErrMissingEnvironmentVariable{
			// silently ignore TOTP passcode warning, since it is not a common auth method
			EnvironmentVariable: "OS_PASSWORD",
		}
		return nil, err
	}

	if (applicationCredentialID != "" || applicationCredentialName != "") && applicationCredentialSecret == "" {
		err := gophercloud.ErrMissingEnvironmentVariable{
			EnvironmentVariable: "OS_APPLICATION_CREDENTIAL_SECRET",
		}
		return nil, err
	}

	if projectName != "" && projectID == "" && projectDomainID == "" && projectDomainName == "" {
		err := gophercloud.ErrMissingAnyoneOfEnvironmentVariables{
			EnvironmentVariables: []string{"OS_PROJECT_ID", "OS_PROJECT_DOMAIN_ID", "OS_PROJECT_DOMAIN_NAME"},
		}
		return nil, err
	}

	if applicationCredentialID == "" && applicationCredentialName != "" && applicationCredentialSecret != "" {
		if userID == "" && username == "" {
			return nil, gophercloud.ErrMissingAnyoneOfEnvironmentVariables{
				EnvironmentVariables: []string{"OS_USERID", "OS_USERNAME"},
			}
		}
		if username != "" && userDomainID == "" && userDomainName == "" {
			return nil, gophercloud.ErrMissingAnyoneOfEnvironmentVariables{
				EnvironmentVariables: []string{"OS_USER_DOMAIN_ID", "OS_USER_DOMAIN_NAME"},
			}
		}
	}

	ao := &gophercloud.AuthOptionsV3{
		IdentityEndpoint:  authURL,
		AuthType:          authType,
		DomainID:          domainID,
		DomainName:        domainName,
		ProjectDomainID:   projectDomainID,
		ProjectDomainName: projectDomainName,
		ProjectID:         projectID,
		ProjectName:       projectName,
		SystemScope:       systemScope,
		//TrustID:                     trustID,
		UserDomainID:   userDomainID,
		UserDomainName: userDomainName,
		Username:       username,
		UserID:         userID,
		Password:       password,
		Passcode:       passcode,
		//TokenID:                     tokenID,
		ApplicationCredentialID:     applicationCredentialID,
		ApplicationCredentialName:   applicationCredentialName,
		ApplicationCredentialSecret: applicationCredentialSecret,
	}

	return ao, nil
}

/*
AuthOptionsFromEnv fills out an identity.AuthOptions structure with the
settings found on the various OpenStack OS_* environment variables.

The following variables provide sources of truth: OS_AUTH_URL, OS_USERNAME,
OS_PASSWORD and OS_PROJECT_ID.

Of these, OS_USERNAME, OS_PASSWORD, and OS_AUTH_URL must have settings,
or an error will result.  OS_PROJECT_ID, is optional.

OS_TENANT_ID and OS_TENANT_NAME are deprecated forms of OS_PROJECT_ID and
OS_PROJECT_NAME and the latter are expected against a v3 auth api.

If OS_PROJECT_ID and OS_PROJECT_NAME are set, they will still be referred
as "tenant" in Gophercloud.

If OS_PROJECT_NAME is set, it requires OS_PROJECT_ID to be set as well to
handle projects not on the default domain.

To use this function, first set the OS_* environment variables (for example,
by sourcing an `openrc` file), then:

	opts, err := openstack.AuthOptionsFromEnv()
	provider, err := openstack.AuthenticatedClient(context.TODO(), opts)
*/
func AuthOptionsFromEnv() (gophercloud.AuthOptions, error) {
	apiVersion := os.Getenv("OS_IDENTITY_API_VERSION")
	if apiVersion != "" {
		apiVersion = "3"
	}

	switch apiVersion {
	case "3":
		return authOptionsFromEnvV3()
	case "2":
		return authOptionsFromEnvV2()
	default:
		// TODO: error
		return nil, nil
	}
}
