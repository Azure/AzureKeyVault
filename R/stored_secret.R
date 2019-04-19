#' Stored secret object
#'
#' This class represents a secret stored in a vault.
#'
#' @docType class
#'
#' @section Fields:
#' This class provides the following fields:
#' - `value`: The value of the secret.
#' - `id`: The ID of the secret.
#' - `kid`: If this secret backs a certificate, the ID of the corresponding key.
#' - `managed`: Whether this secret's lifetime is managed by Key Vault. TRUE if the secret backs a certificate.
#' - `contentType`: The content type of the secret.
#'
#' @section Methods:
#' This class provides the following methods:
#' ```
#' update_attributes(attributes=vault_object_attrs(), ...)
#' list_versions()
#' set_version(version=NULL)
#' delete(confirm=TRUE)
#' ```
#' @section Arguments:
#' - `attributes`: For `update_attributes`, the new attributes for the object, such as the expiry date and activation date. A convenient way to provide this is via the [vault_object_attrs] helper function.
#' - `...`: For `update_attributes`, additional secret-specific properties to update. See [secrets].
#' - `version`: For `set_version`, the version ID or NULL for the current version.
#' - `confirm`: For `delete`, whether to ask for confirmation before deleting the secret.
#'
#' @section Details:
#' A secret can have multiple _versions_, which are automatically generated when a secret is created with the same name as an existing secret. By default, the most recent (current) version is used for secret operations; use `list_versions` and `set_version` to change the version.
#'
#' @section Value:
#' For `list_versions`, a vector of secret version IDs.
#'
#' For `set_version`, the secret object with the updated version.
#'
#' @seealso
#' [secrets]
#'
#' [Azure Key Vault documentation](https://docs.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://docs.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' vault <- key_vault$new("mykeyvault")
#'
#' vault$secrets$create("mynewsecret", "secret text")
#' # new version of an existing secret
#' vault$secrets$create("mynewsecret", "extra secret text"))
#'
#' secret <- vault$secrets$get("mynewsecret")
#' vers <- secret$list_versions()
#' secret$set_version(vers[2])
#'
#' secret$value  # "secret text"
#'
#' }
#' @name storage_account
#' @rdname storage_account
NULL

stored_secret <- R6::R6Class("stored_secret", inherit=stored_object,

public=list(

    type="secrets",

    id=NULL,
    kid=NULL,
    value=NULL,
    contentType=NULL,

    list_versions=function()
    {
        lst <- lapply(get_vault_paged_list(self$do_operation("versions", version=NULL), self$token), function(props)
        {
            content_type <- if(!is_empty(props$contentType))
                props$contentType
            else NA
            attr <- props$attributes
            data.frame(
                version=basename(props$id),
                content_type=content_type,
                created=int_to_date(attr$created),
                updated=int_to_date(attr$updated),
                expiry=int_to_date(attr$exp),
                not_before=int_to_date(attr$nbf),
                stringsAsFactors=FALSE
            )
        })
        do.call(rbind, lst)
    }
))
