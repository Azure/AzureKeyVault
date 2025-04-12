#' Key vault resource class
#'
#' Class representing a key vault, exposing methods for working with it.
#'
#' @docType class
#' @section Methods:
#' The following methods are available, in addition to those provided by the [AzureRMR::az_resource] class:
#' - `new(...)`: Initialize a new key vault object. See 'Initialization'.
#' - `add_principal(principal, ...)`: Add an access policy for a user or service principal. See 'Access policies' below.
#' - `get_principal(principal)`: Retrieve an access policy for a user or service principal.
#' - `remove_principal(principal)`: Remove access for a user or service principal.
#' - `get_endpoint()`: Return the vault endpoint. See 'Endpoint' below.
#'
#' @section Initialization:
#' Initializing a new object of this class can either retrieve an existing key vault, or create a new vault on the host. The recommended way to initialize an object is via the `get_key_vault`, `create_key_vault` or `list_key_vaults` methods of the [AzureRMR::az_resource_group] class, which handle the details automatically.
#'
#' @section Access policies:
#' Client access to a key vault is governed by its access policies, which are set on a per-principal basis. Each principal (user or service) can have different permissions granted, for keys, secrets, certificates, and storage accounts.
#'
#' To grant access, use the `add_principal` method. This has signature
#'
#' ```
#' add_principal(principal, tenant = NULL,
#'               key_permissions = "all",
#'               secret_permissions = "all",
#'               certificate_permissions = "all",
#'               storage_permissions = "all")
#'```
#' The `principal` can be a GUID, an object of class `vault_access_policy`, or a user, app or service principal object from the AzureGraph package. Note that the app ID of a registered app is not the same as the ID of its service principal.
#'
#' The tenant must be a GUID; if this is NULL, it will be taken from the tenant of the key vault resource.
#'
#' Here are the possible permissions for keys, secrets, certificates, and storage accounts. The permission "all" means to grant all permissions.
#' - Keys: "get", "list", "update", "create", "import", "delete", "recover", "backup", "restore", "decrypt", "encrypt", "unwrapkey", "wrapkey", "verify", "sign", "purge"
#' - Secrets: "get", "list", "set", "delete", "recover", "backup", "restore", "purge"
#' - Certificates: "get", "list", "update", "create", "import", "delete", "recover", "backup", "restore", "managecontacts", "manageissuers", "getissuers", "listissuers", "setissuers", "deleteissuers", "purge"
#' - Storage accounts: "get", "list", "update", "set", "delete", "recover", "backup", "restore", "regeneratekey", "getsas", "listsas", "setsas", "deletesas", "purge"
#'
#' To revoke access, use the `remove_principal` method. To view the current access policy, use `get_principal` or `list_principals`.
#'
#' @section Endpoint:
#' The client-side interaction with a key vault is via its _endpoint_, which is usually at the URL `https://[vaultname].vault.azure.net`. The `get_endpoint` method returns an R6 object of class `key_vault`, which represents the endpoint. Authenticating with the endpoint is done via an OAuth token; the necessary credentials are taken from the current Resource Manager client in use, or you can supply your own.
#'
#' ```
#' get_endpoint(tenant = self$token$tenant,
#'              app = self$token$client$client_id,
#'              password = self$token$client$client_secret, ...)
#'```
#' To access the key vault independently of Resource Manager (for example if you are a user without admin or owner access to the vault resource), use the [key_vault] function.
#'
#' @seealso
#' [vault_access_policy], [key_vault]
#' [create_key_vault], [get_key_vault], [delete_key_vault],
#' [AzureGraph::get_graph_login], [AzureGraph::az_user], [AzureGraph::az_app], [AzureGraph::az_service_principal]
#'
#' [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://learn.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' # recommended way of retrieving a resource: via a resource group object
#' kv <- resgroup$get_key_vault("mykeyvault")
#'
#' # list principals that have access to the vault
#' kv$list_principals()
#'
#' # grant a user full access (the default)
#' usr <- AzureGraph::get_graph_login()$
#'     get_user("username@aadtenant.com")
#' kv$add_principal(usr)
#'
#' # grant a service principal read access to keys and secrets only
#' svc <- AzureGraph::get_graph_login()$
#'     get_service_principal(app_id="app_id")
#' kv$add_principal(svc,
#'     key_permissions=c("get", "list"),
#'     secret_permissions=c("get", "list"),
#'     certificate_permissions=NULL,
#'     storage_permissions=NULL)
#
#' # alternatively, supply a vault_access_policy with the listed permissions
#' pol <- vault_access_policy(svc,
#'     key_permissions=c("get", "list"),
#'     secret_permissions=c("get", "list"),
#'     certificate_permissions=NULL,
#'     storage_permissions=NULL)
#' kv$add_principal(pol)
#'
#' # revoke access
#' kv$remove_access(svc)
#'
#' # get the endpoint object
#' vault <- kv$get_endpoint()
#'
#' }
#' @export
az_key_vault <- R6::R6Class("az_key_vault", inherit=AzureRMR::az_resource,

public=list(

    add_principal=function(principal, tenant=NULL,
        key_permissions="all", secret_permissions="all", certificate_permissions="all", storage_permissions="all")
    {
        if(!inherits(principal, "vault_access_policy"))
            principal <- vault_access_policy(
                principal,
                tenant,
                key_permissions,
                secret_permissions,
                certificate_permissions,
                storage_permissions
            )

        # un-nullify tenant ID using tenant of resource
        if(is.null(principal$tenantId))
            principal$tenantId <- self$properties$tenantId

        props <- list(accessPolicies=list(unclass(principal)))

        self$do_operation("accessPolicies/add",
            body=list(properties=props), encode="json", http_verb="PUT")

        self$sync_fields()
        invisible(self)
    },

    get_principal=function(principal)
    {
        principal <- find_principal(principal)

        pols <- self$properties$accessPolicies
        i <- sapply(pols, function(obj) obj$objectId == principal)
        if(!any(i))
            stop("No access policy for principal '", principal, "'", call.=FALSE)

        pol <- pols[[which(i)]]
        vault_access_policy(pol$objectId, pol$tenantId,
            pol$permissions$keys, pol$permissions$secrets, pol$permissions$certificates, pol$permissions$storage)
    },

    remove_principal=function(principal)
    {
        pol <- self$get_principal(principal)
        props <- list(accessPolicies=list(unclass(pol)))

        self$do_operation("accessPolicies/remove",
            body=list(properties=props), encode="json", http_verb="PUT")

        self$sync_fields()
        invisible(self)
    },

    list_principals=function()
    {
        lapply(self$properties$accessPolicies, function(pol)
            vault_access_policy(pol$objectId, pol$tenantId,
                pol$permissions$keys, pol$permissions$secrets, pol$permissions$certificates, pol$permissions$storage)
        )
    },

    get_endpoint=function(tenant=self$token$tenant, app=self$token$client$client_id,
                          password=self$token$client$client_secret, ...)
    {
        url <- self$properties$vaultUri
        key_vault(url=url, tenant=tenant, app=app, password=password, ...)
    },

    delete=function(confirm=TRUE, wait=FALSE, purge=FALSE)
    {
        if(purge) wait <- TRUE

        super$delete(confirm, wait)
        if(purge && isTRUE(self$properties$enableSoftDelete))
        {
            sub <- az_subscription$new(self$token, self$subscription)
            sub$purge_key_vault(self$name, self$location, confirm)
        }
        invisible(NULL)
    }
))


#' Specify a key vault access policy
#'
#' @param principal The user or service principal for this access policy. Can be a GUID, or a user, app or service principal object from the AzureGraph package.
#' @param tenant The tenant of the principal.
#' @param key_permissions The permissions to grant for working with keys.
#' @param secret_permissions The permissions to grant for working with secrets.
#' @param certificate_permissions The permissions to grant for working with certificates.
#' @param storage_permissions The permissions to grant for working with storage accounts.
#'
#' @details
#' Client access to a key vault is governed by its access policies, which are set on a per-principal basis. Each principal (user or service) can have different permissions granted, for keys, secrets, certificates, and storage accounts.
#'
#' Here are the possible permissions. The permission "all" means to grant all permissions.
#' - Keys: "get", "list", "update", "create", "import", "delete", "recover", "backup", "restore", "decrypt", "encrypt", "unwrapkey", "wrapkey", "verify", "sign", "purge"
#' - Secrets: "get", "list", "set", "delete", "recover", "backup", "restore", "purge"
#' - Certificates: "get", "list", "update", "create", "import", "delete", "recover", "backup", "restore", "managecontacts", "manageissuers", "getissuers", "listissuers", "setissuers", "deleteissuers", "purge"
#' - Storage accounts: "get", "list", "update", "set", "delete", "recover", "backup", "restore", "regeneratekey", "getsas", "listsas", "setsas", "deletesas", "purge"
#'
#' @return
#' An object of class `vault_access_policy`, suitable for creating a key vault resource.
#'
#' @seealso
#' [create_key_vault], [az_key_vault]
#'
#' [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://learn.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' # default is to grant full access
#' vault_access_policy("user_id")
#'
#' # use AzureGraph to specify a user via their email address rather than a GUID
#' usr <- AzureGraph::get_graph_login()$get_user("username@aadtenant.com")
#' vault_access_policy(usr)
#'
#' # grant a service principal read access to keys and secrets only
#' svc <- AzureGraph::get_graph_login()$
#'     get_service_principal(app_id="app_id")
#' vault_access_policy(svc,
#'     key_permissions=c("get", "list"),
#'     secret_permissions=c("get", "list"),
#'     certificate_permissions=NULL,
#'     storage_permissions=NULL)
#'
#' }
#' @export
vault_access_policy <- function(principal, tenant=NULL,
                                key_permissions="all",
                                secret_permissions="all",
                                certificate_permissions="all",
                                storage_permissions="all")
{
    principal <- find_principal(principal)

    key_permissions <- verify_key_permissions(key_permissions)
    secret_permissions <- verify_secret_permissions(secret_permissions)
    certificate_permissions <- verify_certificate_permissions(certificate_permissions)
    storage_permissions <- verify_storage_permissions(storage_permissions)

    obj <- list(
        tenantId=tenant,
        objectId=principal,
        permissions=list(
            keys=I(key_permissions),
            secrets=I(secret_permissions),
            certificates=I(certificate_permissions),
            storage=I(storage_permissions)
        )
    )
    class(obj) <- "vault_access_policy"
    obj
}


#' @export
print.vault_access_policy <- function(x, ...)
{
    cat("Tenant:", if(is.null(x$tenantId)) "<default>" else x$tenantId, "\n")
    cat("Principal:", x$objectId, "\n")
    cat("Key permissions:\n")
    cat(strwrap(paste(x$permissions$keys, collapse=", "), indent=4, exdent=4), sep="\n")
    cat("Secret permissions:\n")
    cat(strwrap(paste(x$permissions$secrets, collapse=", "), indent=4, exdent=4), sep="\n")
    cat("Certificate permissions:\n")
    cat(strwrap(paste(x$permissions$certificates, collapse=", "), indent=4, exdent=4), sep="\n")
    cat("Storage account permissions:\n")
    cat(strwrap(paste(x$permissions$storage, collapse=", "), indent=4, exdent=4), sep="\n")
    cat("\n")
    invisible(x)
}


find_principal <- function(principal)
{
    if(is_user(principal) || is_service_principal(principal))
        principal$properties$id
    else if(is_app(principal))
        principal$get_service_principal()$properties$id
    else if(inherits(principal, "vault_access_policy"))
        principal$objectId
    else if(!is_guid(principal))
        stop("Must supply a valid principal ID or object", call.=FALSE)
    else AzureAuth::normalize_guid(principal)
}


verify_key_permissions <- function(perms)
{
    key_perms <- c("get", "list", "update", "create", "import", "delete", "recover", "backup", "restore",
                   "decrypt", "encrypt", "unwrapkey", "wrapkey", "verify", "sign", "purge")

    verify_permissions(perms, key_perms)
}


verify_secret_permissions <- function(perms)
{
    secret_perms <- c("get", "list", "set", "delete", "recover", "backup", "restore", "purge")

    verify_permissions(perms, secret_perms)
}


verify_certificate_permissions <- function(perms)
{
    certificate_perms <- c("get", "list", "update", "create", "import", "delete", "recover", "backup", "restore",
                           "managecontacts", "manageissuers", "getissuers", "listissuers", "setissuers",
                           "deleteissuers", "purge")

    verify_permissions(perms, certificate_perms)
}


verify_storage_permissions <- function(perms)
{
    storage_perms <- c("backup", "delete", "deletesas", "get", "getsas", "list", "listsas",
                       "purge", "recover", "regeneratekey", "restore", "set", "setsas", "update")

    verify_permissions(perms, storage_perms)
}


verify_permissions <- function(perms, all_perms)
{
    perms <- tolower(unlist(perms))

    if(length(perms) == 1 && perms == "all")
        return(all_perms)
    else if(!all(perms %in% all_perms))
        stop("Invalid permissions")

    perms
}

