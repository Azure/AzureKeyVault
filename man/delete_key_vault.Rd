% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/add_methods.R
\name{delete_key_vault}
\alias{delete_key_vault}
\title{Delete an Azure Key Vault}
\description{
Method for the \link[AzureRMR:az_resource_group]{AzureRMR::az_resource_group} class.
}
\details{
Deleting a key vault that has soft-deletion enabled does not permanently remove it. Instead the resource is held for a given retention period (90 days), during which it can be recovered, essentially undoing the deletion.

To see what soft-deleted key vaults exist, call the \code{list_deleted_key_vaults} method. To recover a soft-deleted key vault, call the \code{create_key_vault} method from the vault's original resource group, with the vault name. To purge (permanently delete) it, call the \code{purge_key_vault} method.
}
\section{Usage}{


\if{html}{\out{<div class="sourceCode">}}\preformatted{delete_key_vault(name, confirm=TRUE, wait=FALSE, purge=FALSE)
}\if{html}{\out{</div>}}
}

\section{Arguments}{

\itemize{
\item \code{name}: The name of the key vault.
\item \code{confirm}: Whether to ask for confirmation before deleting.
\item \code{wait}: Whether to wait until the deletion is complete. Note that \code{purge=TRUE} will set \code{wait=TRUE} as well.
\item \code{purge}: For a vault with the soft-deletion feature enabled, whether to purge it as well (hard delete). Has no effect if the vault does not have soft-deletion enabled.
}
}

\section{Value}{

NULL on successful deletion.
}

\examples{
\dontrun{

rg <- AzureRMR::get_azure_login()$
    get_subscription("subscription_id")$
    get_resource_group("rgname")

# assuming the vault has soft-delete enabled
rg$delete_key_vault("mykeyvault", purge=FALSE)

# recovering a soft-deleted key vault
rg$create_key_vault("mykeyvault")

# deleting it for good
rg$delete_key_vault("mykeyvault", purge=FALSE)

}
}
\seealso{
\link{create_key_vault}, \link{get_key_vault}, \link{purge_key_vault}, \link{list_deleted_key_vaults}, \link{az_key_vault},

\href{https://learn.microsoft.com/en-us/azure/key-vault/}{Azure Key Vault documentation},
\href{https://learn.microsoft.com/en-us/rest/api/keyvault}{Azure Key Vault API reference}
}
