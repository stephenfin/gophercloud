package auth

import "github.com/gophercloud/gophercloud/v2"

// TODO: Add ProjectDomainID, ProjectDomainName
type Scope struct {
	// Domain ID to scope to
	DomainID string
	// Domain name to scope to
	DomainName string
	// Project ID to scope to
	ProjectID string
	// Project name to scope to
	ProjectName string
	// Scope for system operations
	System bool
	// ID of the trust to use as a trustee user
	TrustID string
}

func (opts *Scope) ToScopeMap() (map[string]any, error) {
	if opts.System {
		return map[string]any{
			"system": map[string]any{
				"all": true,
			},
		}, nil
	}

	if opts.TrustID != "" {
		return map[string]any{
			"OS-TRUST:trust": map[string]string{
				"id": opts.TrustID,
			},
		}, nil
	}

	if opts.ProjectName != "" {
		// ProjectName provided: either DomainID or DomainName must also be supplied.
		// ProjectID may not be supplied.
		if opts.DomainID == "" && opts.DomainName == "" {
			return nil, gophercloud.ErrScopeDomainIDOrDomainName{}
		}
		if opts.ProjectID != "" {
			return nil, gophercloud.ErrScopeProjectIDOrProjectName{}
		}

		if opts.DomainID != "" {
			// ProjectName + DomainID
			return map[string]any{
				"project": map[string]any{
					"name":   &opts.ProjectName,
					"domain": map[string]any{"id": &opts.DomainID},
				},
			}, nil
		}

		if opts.DomainName != "" {
			// ProjectName + DomainName
			return map[string]any{
				"project": map[string]any{
					"name":   &opts.ProjectName,
					"domain": map[string]any{"name": &opts.DomainName},
				},
			}, nil
		}
	} else if opts.ProjectID != "" {
		// ProjectID provided. ProjectName, DomainID, and DomainName may not be provided.
		if opts.DomainID != "" {
			return nil, gophercloud.ErrScopeProjectIDAlone{}
		}
		if opts.DomainName != "" {
			return nil, gophercloud.ErrScopeProjectIDAlone{}
		}

		// ProjectID
		return map[string]any{
			"project": map[string]any{
				"id": &opts.ProjectID,
			},
		}, nil
	} else if opts.DomainID != "" {
		// DomainID provided. ProjectID, ProjectName, and DomainName may not be provided.
		if opts.DomainName != "" {
			return nil, gophercloud.ErrScopeDomainIDOrDomainName{}
		}

		// DomainID
		return map[string]any{
			"domain": map[string]any{
				"id": &opts.DomainID,
			},
		}, nil
	} else if opts.DomainName != "" {
		// DomainName
		return map[string]any{
			"domain": map[string]any{
				"name": &opts.DomainName,
			},
		}, nil
	}

	return nil, nil
}
