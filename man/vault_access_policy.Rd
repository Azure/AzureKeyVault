% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/az_vault.R
\name{vault_access_policy}
\alias{vault_access_policy}
\title{Specify a key vault access policy}
\usage{
vault_access_policy(
  principal,
  tenant = NULL,
  key_permissions = "all",
  secret_permissions = "all",
  certificate_permissions = "all",
  storage_permissions = "all"
)
}
\arguments{
\item{principal}{The user or service principal for this access policy. Can be a GUID, or a user, app or service principal object from the AzureGraph package.}

\item{tenant}{The tenant of the principal.}

\item{key_permissions}{The permissions to grant for working with keys.}

\item{secret_permissions}{The permissions to grant for working with secrets.}

\item{certificate_permissions}{The permissions to grant for working with certificates.}

\item{storage_permissions}{The permissions to grant for working with storage accounts.}
}
\value{
An object of class \code{vault_access_policy}, suitable for creating a key vault resource.
}
\description{
Specify a key vault access policy
}
\details{
Client access to a key vault is governed by its access policies, which are set on a per-principal basis. Each principal (user or service) can have different permissions granted, for keys, secrets, certificates, and storage accounts.

Here are the possible permissions. The permission "all" means to grant all permissions.
\itemize{
\item Keys: "get", "list", "update", "create", "import", "delete", "recover", "backup", "restore", "decrypt", "encrypt", "unwrapkey", "wrapkey", "verify", "sign", "purge"
\item Secrets: "get", "list", "set", "delete", "recover", "backup", "restore", "purge"
\item Certificates: "get", "list", "update", "create", "import", "delete", "recover", "backup", "restore", "managecontacts", "manageissuers", "getissuers", "listissuers", "setissuers", "deleteissuers", "purge"
\item Storage accounts: "get", "list", "update", "set", "delete", "recover", "backup", "restore", "regeneratekey", "getsas", "listsas", "setsas", "deletesas", "purge"
}
}
\examples{
\dontrun{

# default is to grant full access
vault_access_policy("user_id")

# use AzureGraph to specify a user via their email address rather than a GUID
usr <- AzureGraph::get_graph_login()$get_user("username@aadtenant.com")
vault_access_policy(usr)

# grant a service principal read access to keys and secrets only
svc <- AzureGraph::get_graph_login()$
    get_service_principal(app_id="app_id")
vault_access_policy(svc,
    key_permissions=c("get", "list"),
    secret_permissions=c("get", "list"),
    certificate_permissions=NULL,
    storage_permissions=NULL)

}
}
\seealso{
\link{create_key_vault}, \link{az_key_vault}

\href{https://learn.microsoft.com/en-us/azure/key-vault/}{Azure Key Vault documentation},
\href{https://learn.microsoft.com/en-us/rest/api/keyvault}{Azure Key Vault API reference}
}
