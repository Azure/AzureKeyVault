az_vault=R6::R6Class("az_vault", inherit=AzureRMR::az_resource,

public=list(

    add_principal=function(principal, key_permissions="Get", secret_permissions="Get", certificate_permissions="Get")
    {
        principal <- private$find_principal(principal)
        tenant <- self$properties$tenantId

        props <- list(accessPolicies=list(
            vault_access_policy(principal, tenant, key_permissions, secret_permissions, certificate_permissions)
        ))

        self$do_operation("accessPolicies/add",
            body=list(properties=props), encode="json", http_verb="PUT")

        self$sync_fields()
        invisible(self)
    },

    get_principal=function(principal)
    {
        principal <- private$find_principal(principal)

        pols <- self$properties$accessPolicies
        i <- sapply(pols, function(obj) obj%principalId == principal)
        if(!any(i))
            stop("No access policy for principal '", principal, "'", call.=FALSE)

        pol <- pols[[which(i)]]
        vault_access_policy(pol$objectId, pol$tenantId,
            pol$permissions$keys, pol$permissions$secrets, pol$permissions$certificates)
    },

    remove_principal=function(principal)
    {
        principal <- private$find_principal(principal)
        tenant <- self$properties$tenantId

        props <- list(accessPolicies=list(
            vault_access_policy(principal, tenant, list(), list(), list())
        ))

        self$do_operation("accessPolicies/remove",
            body=list(properties=props), encode="json", http_verb="PUT")

        self$sync_fields()
        invisible(self)
    },

    list_principals=function()
    {
        lapply(self$properties$accessPolicies, function(pol)
            vault_access_policy(pol$objectId, pol$tenantId,
                pol$permissions$keys, pol$permissions$secrets, pol$permissions$certificates)
        )
    },
        
    get_vault_endpoint=function(app=self$token$client$client_id, password=self$token$client$client_secret, ...)
    {
        url <- self$properties$vaultUri
        token <- get_azure_token(url, self$token$tenant, app=app, password=password, ...)
        get_vault_login(token=token)
    }
),

private=list(

    find_principal=function(principal)
    {
        if(is_user(principal) || is_service_principal(principal))
            principal$properties$id
        else if(is_app(principal))
            principal$get_service_principal()$properties$id
        else if(!is_guid(principal))
            stop("Must supply a valid principal ID or object", call.=FALSE)
        else principal
    }
))


vault_access_policy <- function(principal, tenant, key_permissions, secret_permissions, certificate_permissions)
{
    key_permissions <- unlist(key_permissions)
    secret_permissions <- unlist(secret_permissions)
    certificate_permissions <- unlist(certificate_permissions)

    obj <- list(
        tenantId=tenant,
        objectId=principal,
        permissions=list(
            keys=I(key_permissions),
            secrets=I(secret_permissions),
            certificates=I(certificate_permissions)
        )
    )
    class(obj) <- "vault_access_policy"
    obj
}


print.vault_access_policy <- function(x, ...)
{
    cat("Key vault access policy\n")
    cat("  Tenant:", x$tenantId, "\n")
    cat("  Principal:", x$objectId, "\n")
    cat("  Key permissions:\n    ")
    cat(x$permissions$keys, sep=", ")
    cat("\n  Secret permissions:\n    ")
    cat(x$permissions$secrets, sep=", ")
    cat("\n  Certificate permissions:\n    ")
    cat(x$permissions$certificates, sep=", ")
    cat("\n")
    invisible(x)
}

