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
#' - `allow_vm_access`: Whether to allow Azure virtual machines to retrieve certificates from the vault.
#' - `allow_arm_access`: Whether to allow Azure Resource Manager to retrieve secrets from the vault for template deployment purposes.
#' - `allow_disk_encryption_access`: Whether to allow Azure Disk Encryption to retrieve secrets and keys from the vault.
#' - `soft_delete`: Whether soft-deletion should be enabled for this vault. Soft-deletion is a feature which protects both the vault itself and its contents from accidental/malicious deletion; see below.
#' - `purge_protection`: Whether purge protection is enabled. If this is TRUE and soft-deletion is enabled for the vault, manual purges are not allowed. Has no effect if `soft_delete=FALSE`.
#' - `...`: Other named arguments to pass to the [az_key_vault] initialization function.
#' - `wait`: Whether to wait for the resource creation to complete before returning.
#'
#' @section Details:
#' This method deploys a new key vault resource, with parameters given by the arguments. A key vault is a secure facility for storing and managing encryption keys, certificates, storage account keys, and generic secrets.
#'
#' A new key vault will have access granted to the user or service principal used to sign in to the Azure Resource Manager client. To manage access policies after creation, use the `add_principal`, `list_principals` and `remove_principal` methods of the key vault object.
#'
#' Key Vault's soft delete feature allows recovery of the deleted vaults and vault objects, known as soft-delete. Specifically, it addresses the following scenarios:
#' - Support for recoverable deletion of a key vault
#' - Support for recoverable deletion of key vault objects (keys, secrets, certificates)
#'
#' With this feature, the delete operation on a key vault or key vault object is a soft-delete, effectively holding the resources for a given retention period (90 days), while giving the appearance that the object is deleted. The service further provides a mechanism for recovering the deleted object, essentially undoing the deletion.
#'
#' Soft-deleted vaults can be purged (permanently removed) by calling the `purge_key_vault` method for the resource group or subscription classes. The purge protection optional feature provides an additional layer of protection by forbidding manual purges; when this is on, a vault or an object in deleted state cannot be purged until the retention period of 90 days has passed.
#'
#' To see what soft-deleted key vaults exist, call the `list_deleted_key_vaults` method. To recover a soft-deleted key vault, call the `create_key_vault` method from the vault's original resource group, with the vault name. To purge (permanently delete) it, call the `purge_key_vault` method.
#'
#' @section Value:
#' An object of class `az_key_vault` representing the created key vault.
#'
#' @seealso
#' [get_key_vault], [delete_key_vault], [purge_key_vault], [az_key_vault], [vault_access_policy]
#'
#' [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://learn.microsoft.com/en-us/rest/api/keyvault)
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
#' [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://learn.microsoft.com/en-us/rest/api/keyvault)
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
#' delete_key_vault(name, confirm=TRUE, wait=FALSE, purge=FALSE)
#' ```
#' @section Arguments:
#' - `name`: The name of the key vault.
#' - `confirm`: Whether to ask for confirmation before deleting.
#' - `wait`: Whether to wait until the deletion is complete. Note that `purge=TRUE` will set `wait=TRUE` as well.
#' - `purge`: For a vault with the soft-deletion feature enabled, whether to purge it as well (hard delete). Has no effect if the vault does not have soft-deletion enabled.
#' @details
#' Deleting a key vault that has soft-deletion enabled does not permanently remove it. Instead the resource is held for a given retention period (90 days), during which it can be recovered, essentially undoing the deletion.
#'
#' To see what soft-deleted key vaults exist, call the `list_deleted_key_vaults` method. To recover a soft-deleted key vault, call the `create_key_vault` method from the vault's original resource group, with the vault name. To purge (permanently delete) it, call the `purge_key_vault` method.
#'
#' @section Value:
#' NULL on successful deletion.
#'
#' @seealso
#' [create_key_vault], [get_key_vault], [purge_key_vault], [list_deleted_key_vaults], [az_key_vault],
#'
#' [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://learn.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' rg <- AzureRMR::get_azure_login()$
#'     get_subscription("subscription_id")$
#'     get_resource_group("rgname")
#'
#' # assuming the vault has soft-delete enabled
#' rg$delete_key_vault("mykeyvault", purge=FALSE)
#'
#' # recovering a soft-deleted key vault
#' rg$create_key_vault("mykeyvault")
#'
#' # deleting it for good
#' rg$delete_key_vault("mykeyvault", purge=FALSE)
#'
#' }
NULL


#' Purge a deleted Azure Key Vault
#'
#' Method for the [AzureRMR::az_subscription] and [AzureRMR::az_resource_group] classes.
#'
#' @rdname purge_key_vault
#' @name purge_key_vault
#' @aliases purge_key_vault
#'
#' @section Usage:
#' ```
#' purge_key_vault(name, location, confirm=TRUE)
#' ```
#' @section Arguments:
#' - `name`,`location`: The name and location of the key vault.
#' - `confirm`: Whether to ask for confirmation before permanently deleting the vault.
#' @details
#' This method permanently deletes a soft-deleted key vault. Note that it will fail if the vault has purge protection enabled.
#'
#' @section Value:
#' NULL on successful purging.
#'
#' @seealso
#' [create_key_vault], [get_key_vault], [delete_key_vault], [list_deleted_key_vaults], [az_key_vault],
#'
#' [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://learn.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' rg <- AzureRMR::get_azure_login()$
#'     get_subscription("subscription_id")$
#'     get_resource_group("rgname")
#'
#' # assuming the vault has soft-delete enabled, and is in the same location as its RG
#' rg$delete_key_vault("mykeyvault")
#' rg$purge_key_vault("mykeyvault", rg$location)
#'
#' }
NULL


#' List soft-deleted Key Vaults
#'
#' Method for the [AzureRMR::az_subscription] class.
#'
#' @rdname list_deleted_key_vaults
#' @name list_deleted_key_vaults
#' @aliases list_deleted_key_vaults
#'
#' @section Usage:
#' ```
#' list_deleted_key_vaults()
#' ```
#' @section Value:
#' This method returns a data frame with the following columns:
#' - `name`: The name of the deleted key vault.
#' - `location`: The location (region) of the vault.
#' - `deletion_date`: When the vault was soft-deleted.
#' - `purge_date`: When the vault is scheduled to be purged (permanently deleted).
#' - `protected`: Whether the vault has purge protection enabled. If TRUE, manual attempts to purge it will fail.
#'
#' @seealso
#' [create_key_vault], [get_key_vault], [delete_key_vault], [purge_key_vault], [az_key_vault],
#'
#' [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://learn.microsoft.com/en-us/rest/api/keyvault)
NULL


add_methods <- function()
{
    ## extending AzureRMR classes

    az_resource_group$set("public", "create_key_vault", overwrite=TRUE,
    function(name, location=self$location, initial_access=default_access(), sku="Standard",
             allow_vm_access=FALSE, allow_arm_access=FALSE, allow_disk_encryption_access=FALSE,
             soft_delete=TRUE, purge_protection=FALSE, ..., wait=TRUE)
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
                enableSoftDelete=soft_delete,
                enabledForDeployment=allow_vm_access,
                enabledForTemplateDeployment=allow_arm_access,
                enabledForDiskEncryption=allow_disk_encryption_access,
                sku=list(family="A", name=sku)
            ),
            list(...)
        )
        # only set this if TRUE; API doesn't allow setting it to FALSE
        if(purge_protection && soft_delete)
            props$enablePurgeProtection <- TRUE

        AzureKeyVault::az_key_vault$new(self$token, self$subscription, self$name,
            type="Microsoft.KeyVault/vaults", name=name, location=location,
            properties=props, wait=wait)
    })


    az_resource_group$set("public", "get_key_vault", overwrite=TRUE,
    function(name)
    {
        AzureKeyVault::az_key_vault$new(self$token, self$subscription, self$name,
            type="Microsoft.KeyVault/vaults", name=name)
    })


    az_resource_group$set("public", "delete_key_vault", overwrite=TRUE,
    function(name, confirm=TRUE, wait=FALSE, purge=FALSE)
    {
        self$get_key_vault(name)$delete(confirm=confirm, wait=wait, purge=purge)
    })


    az_resource_group$set("public", "purge_key_vault", overwrite=TRUE,
    function(name, location, confirm=TRUE)
    {
        sub <- az_subscription$new(self$token, self$subscription)
        sub$purge_key_vault(name, location, confirm)
    })


    az_resource_group$set("public", "list_key_vaults", overwrite=TRUE,
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


    az_subscription$set("public", "purge_key_vault", overwrite=TRUE,
    function(name, location, confirm=TRUE)
    {
        if(interactive() && confirm)
        {
            msg <- sprintf("Do you really want to purge the key vault '%s'?", name)
            ok <- if(getRversion() < numeric_version("3.5.0"))
            {
                msg <- paste(msg, "(yes/No/cancel) ")
                yn <- readline(msg)
                if (nchar(yn) == 0)
                    FALSE
                else tolower(substr(yn, 1, 1)) == "y"
            }
            else utils::askYesNo(msg, FALSE)
            if(!ok)
                return(invisible(NULL))
        }

        api_version <- self$get_provider_api_version("Microsoft.KeyVault", "deletedVaults")
        op <- file.path("providers/Microsoft.KeyVault/locations", location, "deletedVaults", name, "purge")

        self$do_operation(op, api_version=api_version, http_verb="POST")
        invisible(NULL)
    })


    az_subscription$set("public", "list_deleted_key_vaults", overwrite=TRUE,
    function()
    {
        as_datetime <- function(x)
        {
            as.POSIXct(x, format="%Y-%m-%dT%H:%M:%S", tz="GMT")
        }

        api_version <- self$get_provider_api_version("Microsoft.KeyVault", "deletedVaults")
        res <- self$do_operation("providers/Microsoft.KeyVault/deletedVaults", api_version=api_version)
        lst <- get_paged_list(res, self$token)
        do.call(rbind, lapply(lst, function(x)
        {
            data.frame(
                name=x$name,
                location=x$properties$location,
                deletion_date=as_datetime(x$properties$deletionDate),
                purge_date=as_datetime(x$properties$scheduledPurgeDate),
                protected=isTRUE(x$properties$purgeProtectionEnabled),
                stringsAsFactors=FALSE
            )
        }))
    })
}
