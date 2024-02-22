package testing

import (
	"reflect"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestToTokenV3ScopeMap(t *testing.T) {
	projectID := "685038cd-3c25-4faf-8f9b-78c18e503190"
	projectName := "admin"
	domainID := "e4b515b8-e453-49d8-9cce-4bec244fa84e"
	domainName := "Default"

	var successCases = []struct {
		opts     gophercloud.AuthOptionsV3
		expected map[string]any
	}{
		// System-scoped
		{
			gophercloud.AuthOptionsV3{
				SystemScope: "all",
			},
			map[string]any{
				"system": map[string]any{
					"all": true,
				},
			},
		},
		// Trust-scoped
		{
			gophercloud.AuthOptionsV3{
				TrustID: "05144328-1f7d-46a9-a978-17eaad187077",
			},
			map[string]any{
				"OS-TRUST:trust": map[string]string{
					"id": "05144328-1f7d-46a9-a978-17eaad187077",
				},
			},
		},
		// Project-scoped (ID)
		{
			gophercloud.AuthOptionsV3{
				ProjectID: projectID,
			},
			map[string]any{
				"project": map[string]any{
					"id": &projectID,
				},
			},
		},
		// Project-scoped (name)
		{
			gophercloud.AuthOptionsV3{
				ProjectName: projectName,
				DomainName:  domainName,
			},
			map[string]any{
				"project": map[string]any{
					"name": &projectName,
					"domain": map[string]any{
						"name": &domainName,
					},
				},
			},
		},
		// Domain-scoped (ID)
		{
			gophercloud.AuthOptionsV3{
				DomainID: domainID,
			},
			map[string]any{
				"domain": map[string]any{
					"id": &domainID,
				},
			},
		},
		// Domain-scoped (name)
		{
			gophercloud.AuthOptionsV3{
				DomainName: domainName,
			},
			map[string]any{
				"domain": map[string]any{
					"name": &domainName,
				},
			},
		},
		// Empty with project fallback (ID)
		{
			gophercloud.AuthOptionsV3{
				ProjectID: projectID,
				SystemScope: "",
			},
			map[string]any{
				"project": map[string]any{
					"id": &projectID,
				},
			},
		},
		// Empty with project fallback (name)
		{
			gophercloud.AuthOptionsV3{
				ProjectName: projectName,
				DomainName: domainName,
				SystemScope: "",
			},
			map[string]any{
				"project": map[string]any{
					"name": &projectName,
					"domain": map[string]any{
						"name": &domainName,
					},
				},
			},
		},
		// Empty without fallback
		{
			gophercloud.AuthOptionsV3{
				SystemScope: "",
			},
			nil,
		},
	}
	for _, successCase := range successCases {
		actual, err := successCase.opts.ToTokenV3ScopeMap()
		th.AssertNoErr(t, err)
		th.AssertDeepEquals(t, successCase.expected, actual)
	}

	var failCases = []struct {
		opts     gophercloud.AuthOptionsV3
		expected error
	}{
		// Project-scoped with name but missing domain ID/name
		{
			gophercloud.AuthOptionsV3{
				ProjectName: "admin",
			},
			gophercloud.ErrScopeDomainIDOrDomainName{},
		},
		// Project-scoped with both project name and project ID
		{
			gophercloud.AuthOptionsV3{
				ProjectName: "admin",
				ProjectID:   "685038cd-3c25-4faf-8f9b-78c18e503190",
				DomainName:  "Default",
			},
			gophercloud.ErrScopeProjectIDOrProjectName{},
		},
		// Project-scoped with name and unnecessary domain ID
		{
			gophercloud.AuthOptionsV3{
				ProjectID: "685038cd-3c25-4faf-8f9b-78c18e503190",
				DomainID:  "e4b515b8-e453-49d8-9cce-4bec244fa84e",
			},
			gophercloud.ErrScopeProjectIDAlone{},
		},
		// Project-scoped with name and unnecessary domain name
		{
			gophercloud.AuthOptionsV3{
				ProjectID:  "685038cd-3c25-4faf-8f9b-78c18e503190",
				DomainName: "Default",
			},
			gophercloud.ErrScopeProjectIDAlone{},
		},
		// Domain-scoped with both domain name and domain ID
		{
			gophercloud.AuthOptionsV3{
				DomainID:   "e4b515b8-e453-49d8-9cce-4bec244fa84e",
				DomainName: "Default",
			},
			gophercloud.ErrScopeDomainIDOrDomainName{},
		},
	}
	for _, failCase := range failCases {
		_, err := failCase.opts.ToTokenV3ScopeMap()
		th.AssertDeepEquals(t, reflect.TypeOf(failCase.expected), reflect.TypeOf(err))
	}
}
