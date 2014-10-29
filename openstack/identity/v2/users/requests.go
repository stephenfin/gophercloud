package users

import (
	"github.com/rackspace/gophercloud"
	"github.com/rackspace/gophercloud/pagination"
)

func List(client *gophercloud.ServiceClient) pagination.Pager {
	createPage := func(r pagination.PageResult) pagination.Page {
		return UserPage{pagination.SinglePageBase(r)}
	}

	return pagination.NewPager(client, rootURL(client), createPage)
}
