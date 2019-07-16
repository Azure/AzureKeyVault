# documentation is separate from implementation because roxygen still doesn't know how to handle R6

#' Create Azure key vault
#'
#' Method for the [AzureRMR::az_resource_group] class.
#'
#' @rdname create_key_vault
#' @name create_key_vault
#' @aliases create_key_vault
#' @section Usage:
#' ```
#' create_key_vault(name, location = self$location, initial_access = default_access(),
#'                  sku = "Standard", ..., wait = TRUE)
#' ```
#' @section Arguments:
#' - `name`: The name of the key vault.
#' - `location`: The location/region in which to create the account. Defaults to the resource group location.
#' - `initial_access`: The user or service principals that will have access to the vault. This should be a list of objects of type `[vault_access_policy]`, created by the function of the same name. The default is to grant access to the logged-in user or service principal of the current Resource Manager client.
#' - `sku`: The sku for the vault. Set this to "Premium" to enable the use of hardware security modules (HSMs).
#' - `...`: Other named arguments to pass to the [az_key_vault] initialization function.
#' - `wait`: Whether to wait for the resource creation to complete before returning.
#'
#' @section Details:
#' This method deploys a new key vault resource, with parameters given by the arguments. A key vault is a secure facility for storing and managing encryption keys, certificates, storage account keys, and generic secrets.
#'
#' A new key vault will have access granted to the user or service principal used to sign in to the Azure Resource Manager client. To manage access policies after creation, use the `add_principal`, `list_principals` and `remove_principal` methods of the key vault object.
#'
#' @section Value:
#' An object of class `az_key_vault` representing the created key vault.
#'
#' @seealso
#' [get_key_vault], [delete_key_vault], [az_key_vault], [vault_access_policy]
#'
#' [Azure Key Vault documentation](https://docs.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://docs.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' rg <- AzureRMR::get_azure_login()$
#'     get_subscription("subscription_id")$
#'     get_resource_group("rgname")
#'
#' # create a new key vault
#' rg$create_key_vault("mykeyvault")
#'
#' # create a new key vault, and grant access to a service principal
#' gr <- AzureGraph::get_graph_login()
#' svc <- gr$get_service_principal("app_id")
#' rg$create_key_vault("mykeyvault",
#'     initial_access=list(vault_access_policy(svc, tenant=NULL)))
#'
#' }
NULL


#' Get existing Azure Key Vault
#'
#' Methods for the [AzureRMR::az_resource_group] class.
#'
#' @rdname get_key_vault
#' @name get_key_vault
#' @aliases get_key_vault list_key_vaults
#'
#' @section Usage:
#' ```
#' get_key_vault(name)
#' list_key_vaults()
#' ```
#' @section Arguments:
#' - `name`: For `get_key_vault()`, the name of the key vault.
#'
#' @section Value:
#' For `get_key_vault()`, an object of class `az_key_vault` representing the vault.
#'
#' For `list_key_vaults()`, a list of such objects.
#'
#' @seealso
#' [create_key_vault], [delete_key_vault], [az_key_vault]
#'
#' [Azure Key Vault documentation](https://docs.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://docs.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' rg <- AzureRMR::get_azure_login()$
#'     get_subscription("subscription_id")$
#'     get_resource_group("rgname")
#'
#' rg$list_key_vaults()
#'
#' rg$get_key_vault("mykeyvault")
#'
#' }
NULL


#' Delete an Azure Key Vault
#'
#' Method for the [AzureRMR::az_resource_group] class.
#'
#' @rdname delete_key_vault
#' @name delete_key_vault
#' @aliases delete_key_vault
#'
#' @section Usage:
#' ```
#' delete_key_vault(name, confirm=TRUE, wait=FALSE)
#' ```
#' @section Arguments:
#' - `name`: The name of the key vault.
#' - `confirm`: Whether to ask for confirmation before deleting.
#' - `wait`: Whether to wait until the deletion is complete.
#'
#' @section Value:
#' NULL on successful deletion.
#'
#' @seealso
#' [create_key_vault], [get_key_vault], [az_key_vault],
#'
#' [Azure Key Vault documentation](https://docs.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://docs.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' rg <- AzureRMR::get_azure_login()$
#'     get_subscription("subscription_id")$
#'     get_resource_group("rgname")
#'
#' rg$delete_key_vault("mykeyvault")
#'
#' }
NULL


add_methods <- function()
{
    ## extending AzureRMR classes

    AzureRMR::az_resource_group$set("public", "create_key_vault", overwrite=TRUE,
    function(name, location=self$location, initial_access=default_access(), sku="Standard", ..., wait=TRUE)
    {
        creds <- AzureAuth::decode_jwt(self$token$credentials$access_token)
        tenant <- creds$payload$tid

        default_access <- function()
        {
            principal <- creds$payload$oid
            list(vault_access_policy(principal, tenant, "all", "all", "all", "all"))
        }

        props <- utils::modifyList(
            list(
                tenantId=tenant,
                accessPolicies=lapply(initial_access, function(x)
                {
                    if(is.null(x$tenantId))
                        x$tenantId <- tenant
                    unclass(x)
                }),
                sku=list(family="A", name=sku)
            ),
            list(...)
        )

        AzureKeyVault::az_key_vault$new(self$token, self$subscription, self$name,
            type="Microsoft.KeyVault/vaults", name=name, location=location,
            properties=props, wait=wait)
    })


    AzureRMR::az_resource_group$set("public", "get_key_vault", overwrite=TRUE,
    function(name)
    {
        AzureKeyVault::az_key_vault$new(self$token, self$subscription, self$name,
            type="Microsoft.KeyVault/vaults", name=name)
    })


    AzureRMR::az_resource_group$set("public", "delete_key_vault", overwrite=TRUE,
    function(name, confirm=TRUE, wait=FALSE)
    {
        self$get_key_vault(name)$delete(confirm=confirm, wait=wait)
    })


    AzureRMR::az_resource_group$set("public", "list_key_vaults", overwrite=TRUE,
    function()
    {
        api_version <- az_subscription$
            new(self$token, self$subscription)$
            get_provider_api_version("Microsoft.KeyVault", "vaults")

        lst <- private$rg_op("providers/Microsoft.KeyVault/vaults", api_version=api_version)
        res <- lst$value
        while(!is_empty(lst$nextLink))
        {
            lst <- call_azure_url(self$token, lst$nextLink)
            res <- c(res, lst$value)
        }

        named_list(lapply(res, function(parms)
            AzureKeyVault::az_key_vault$new(self$token, self$subscription, deployed_properties=parms)))
    })
}
