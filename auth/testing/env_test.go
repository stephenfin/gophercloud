package testing

import (
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/auth"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestAuthOptionsFromEnvV2Password(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvV2Password(t)

	opts, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)

	v2Opts, ok := opts.(*auth.AuthOptionsV2)
	th.AssertEquals(t, true, ok)
	th.AssertEquals(t, "http://example.com:5000/v2.0", v2Opts.AuthURL)
	th.AssertEquals(t, nil, v2Opts.Auth) // Auth mechanism not yet implemented
}

func TestAuthOptionsFromEnvV2Token(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvV2Token(t)

	opts, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)

	v2Opts, ok := opts.(*auth.AuthOptionsV2)
	th.AssertEquals(t, true, ok)
	th.AssertEquals(t, "http://example.com:5000/v2.0", v2Opts.AuthURL)
	th.AssertEquals(t, nil, v2Opts.Auth) // Auth mechanism not yet implemented
}

func TestAuthOptionsFromEnvV3Password(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvV3Password(t)

	opts, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)

	v3Opts, ok := opts.(*auth.AuthOptionsV3)
	th.AssertEquals(t, true, ok)
	th.AssertEquals(t, "http://example.com:5000/v3", v3Opts.AuthURL)
	th.AssertEquals(t, "v3password", v3Opts.AuthType)
	th.AssertEquals(t, nil, v3Opts.Auth) // Auth mechanism not yet implemented
}

func TestAuthOptionsFromEnvV3Token(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvV3Token(t)

	opts, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)

	v3Opts, ok := opts.(*auth.AuthOptionsV3)
	th.AssertEquals(t, true, ok)
	th.AssertEquals(t, "http://example.com:5000/v3", v3Opts.AuthURL)
	th.AssertEquals(t, "v3token", v3Opts.AuthType)
	th.AssertEquals(t, nil, v3Opts.Auth) // Auth mechanism not yet implemented
}

func TestAuthOptionsFromEnvV3TOTP(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvV3TOTP(t)

	opts, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)

	v3Opts, ok := opts.(*auth.AuthOptionsV3)
	th.AssertEquals(t, true, ok)
	th.AssertEquals(t, "http://example.com:5000/v3", v3Opts.AuthURL)
	th.AssertEquals(t, "v3totp", v3Opts.AuthType)
	th.AssertEquals(t, nil, v3Opts.Auth) // Auth mechanism not yet implemented
}

func TestAuthOptionsFromEnvV3AppCred(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvV3AppCred(t)

	opts, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)

	v3Opts, ok := opts.(*auth.AuthOptionsV3)
	th.AssertEquals(t, true, ok)
	th.AssertEquals(t, "http://example.com:5000/v3", v3Opts.AuthURL)
	th.AssertEquals(t, "v3applicationcredential", v3Opts.AuthType)
	th.AssertEquals(t, nil, v3Opts.Auth) // Auth mechanism not yet implemented
}

func TestAuthOptionsFromEnvV3AppCredName(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvV3AppCredName(t)

	opts, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)

	v3Opts, ok := opts.(*auth.AuthOptionsV3)
	th.AssertEquals(t, true, ok)
	th.AssertEquals(t, "http://example.com:5000/v3", v3Opts.AuthURL)
	th.AssertEquals(t, "v3applicationcredential", v3Opts.AuthType)
	th.AssertEquals(t, nil, v3Opts.Auth) // Auth mechanism not yet implemented
}

func TestAuthOptionsFromEnvV3ExplicitAuthType(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvV3ExplicitAuthType(t)

	opts, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)

	v3Opts, ok := opts.(*auth.AuthOptionsV3)
	th.AssertEquals(t, true, ok)
	th.AssertEquals(t, "http://example.com:5000/v3", v3Opts.AuthURL)
	th.AssertEquals(t, "v3password", v3Opts.AuthType)
	th.AssertEquals(t, nil, v3Opts.Auth) // Auth mechanism not yet implemented
}

func TestAuthOptionsFromEnvV3WithAuthMethods(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvV3WithAuthMethods(t)

	opts, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)

	v3Opts, ok := opts.(*auth.AuthOptionsV3)
	th.AssertEquals(t, true, ok)
	th.AssertEquals(t, "http://example.com:5000/v3", v3Opts.AuthURL)
	th.AssertEquals(t, "v3password", v3Opts.AuthType)
	th.AssertDeepEquals(t, []string{"password", "totp"}, v3Opts.AuthMethods)
	th.AssertEquals(t, nil, v3Opts.Auth) // Auth mechanism not yet implemented
}

func TestAuthOptionsFromEnvMissingAuthURL(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvMissingAuthURL(t)

	_, err := auth.AuthOptionsFromEnv()
	th.AssertErr(t, err)

	_, ok := err.(gophercloud.ErrMissingEnvironmentVariable)
	th.AssertEquals(t, true, ok)
}

func TestAuthOptionsFromEnvUnsupportedAuthType(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvUnsupportedAuthType(t)

	_, err := auth.AuthOptionsFromEnv()
	th.AssertErr(t, err)

	_, ok := err.(gophercloud.ErrUnsupportedAuthType)
	th.AssertEquals(t, true, ok)
}

func TestAuthOptionsFromEnvNoCredentials(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvNoCredentials(t)

	_, err := auth.AuthOptionsFromEnv()
	th.AssertErr(t, err)

	_, ok := err.(gophercloud.ErrUnsupportedAuthType)
	th.AssertEquals(t, true, ok)
}

func TestAuthOptionsFromEnvV2Direct(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvV2Password(t)

	opts, err := auth.AuthOptionsFromEnvV2()
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "http://example.com:5000/v2.0", opts.AuthURL)
	th.AssertEquals(t, nil, opts.Auth) // Auth mechanism not yet implemented
}

func TestAuthOptionsFromEnvV3Direct(t *testing.T) {
	defer CleanupEnv(t)
	SetupEnvV3Password(t)

	opts, err := auth.AuthOptionsFromEnvV3()
	th.AssertNoErr(t, err)

	v3Opts, ok := opts.(*auth.AuthOptionsV3)
	th.AssertEquals(t, true, ok)
	th.AssertEquals(t, "http://example.com:5000/v3", v3Opts.AuthURL)
	th.AssertEquals(t, "v3password", v3Opts.AuthType)
	th.AssertEquals(t, nil, v3Opts.Auth) // Auth mechanism not yet implemented
}
