package testing

import (
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestCanReauth(t *testing.T) {
	var testCases = []struct {
		name     string
		opts     gophercloud.AuthOptions
		expected bool
	}{
		{
			"Using TOTP so AllowReauth is ignored",
			gophercloud.AuthOptions{
				Passcode:    "foo",
				AllowReauth: true,
			},
			false,
		},
		{
			"AllowReauth is True",
			gophercloud.AuthOptions{
				AllowReauth: true,
			},
			true,
		},
		{
			"AllowReauth is True",
			gophercloud.AuthOptions{
				AllowReauth: false,
			},
			false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := testCase.opts.CanReauth()
			th.AssertEquals(t, testCase.expected, actual)
		})
	}
}
