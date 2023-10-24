

## Configuration Guide 

### Create Google Workspaces Service Account

Use the following process for creating a Google Workspaces service account. 

[Create Service Account](https://support.google.com/a/answer/7378726?hl=en)

The integration module relies on the Gmail & Alert API's and requires the following scopes for operations:

* `https://www.googleapis.com/auth/gmail.readonly`
* `https://www.googleapis.com/auth/apps.alerts`

### Add Delegated Administrator

For Gmail specific API actions the service account must act on behalf of a delegated administrator. It is best practice
to define a dedicated account to perform these actions however it can be any administrator.

### Add internal Google Domains

To restrict lookups to only internal gmail domains, a comma separated list is required.

