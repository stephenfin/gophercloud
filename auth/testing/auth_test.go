package testing

import (
	"testing"

	"github.com/gophercloud/gophercloud/v2/auth"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestAuthOptionsV2Authenticate(t *testing.T) {
	opts := &auth.AuthOptionsV2{
		AuthURL: "http://example.com:5000/v2.0",
		Auth:    nil,
	}

	err := opts.Authenticate()
	th.AssertNoErr(t, err) // Currently returns nil
}

func TestAuthOptionsV3Authenticate(t *testing.T) {
	opts := &auth.AuthOptionsV3{
		AuthURL:  "http://example.com:5000/v3",
		AuthType: "v3password",
		Auth:     nil,
	}

	err := opts.Authenticate()
	th.AssertNoErr(t, err) // Currently returns nil
}
