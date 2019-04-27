#' Stored secrets in Key Vault
#'
#' This class represents the collection of secrets stored in a vault. It provides methods for managing secrets, including creating, importing and deleting secrets, and doing backups and restores.
#'
#' @docType class
#'
#' @section Methods:
#' This class provides the following methods:
#' ```
#' create(name, value, content_type=NULL, attributes=vault_object_attrs(), ...)
#' get(name)
#' delete(name, confirm=TRUE)
#' list()
#' backup(name)
#' restore(backup)
#' ```
#' @section Arguments:
#' - `name`: The name of the secret.
#' - `value`: For `create`, the secret to store. This should be a character string or a raw vector.
#' - `content_type`: For `create`, an optional content type of the secret, such as "application/octet-stream".
#' - `attributes`: Optional attributes for the secret, such as the expiry date and activation date. A convenient way to provide this is via the [vault_object_attrs] helper function.
#' - `...`: For `create`, other named arguments which will be treated as tags.
#' - `backup`: For `restore`, a string representing the backup blob for a secret.
#'
#' @section Value:
#' For `get`, and `create`, an object of class `stored_secret`, representing the secret. The actual value of the secret is in the `value` field.
#'
#' For `list`, a vector of secret names.
#'
#' For `backup`, a string representing the backup blob for a secret. If the secret has multiple versions, the blob will contain all versions.
#'
#' @seealso
#' [vault_object_attrs]
#'
#' [Azure Key Vault documentation](https://docs.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://docs.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' vault <- key_vault("mykeyvault")
#'
#' vault$secrets$create("mysecret", "secret string")
#'
#' vault$secrets$list()
#'
#' secret <- vault$secrets$get("mysecret")
#' secret$value  # 'secret string'
#'
#' # specifying an expiry date
#' today <- Sys.date()
#' vault$secrets$create("mysecret", attributes=vault_object_attrs(expiry_date=today+365))
#'
#' # setting management tags
#' vault$secrets$create("mysecret", tag1="a value", othertag="another value")
#'
#' }
#' @name secrets
#' @rdname secrets
NULL

vault_secrets <- R6::R6Class("vault_secrets", 

public=list(

    token=NULL,
    url=NULL,

    initialize=function(token, url)
    {
        self$token <- token
        self$url <- url
    },

    create=function(name, value, content_type=NULL, attributes=vault_object_attrs(), ...)
    {
        body <- list(value=value, contentType=content_type, attributes=attributes, tags=list(...))

        self$do_operation(name, body=body, encode="json", http_verb="PUT")
        self$get(name)
    },

    get=function(name, version=NULL)
    {
        op <- construct_path(name, version)
        stored_secret$new(self$token, self$url, name, version, self$do_operation(op))
    },

    delete=function(name, confirm=TRUE)
    {
        if(delete_confirmed(confirm, name, "secret"))
            invisible(self$do_operation(name, http_verb="DELETE"))
    },

    list=function()
    {
        sapply(get_vault_paged_list(self$do_operation(), self$token),
            function(props) basename(props$id))
    },

    backup=function(name)
    {
        self$do_operation(construct_path(name, "backup"), http_verb="POST")$value
    },

    restore=function(name, backup)
    {
        stopifnot(is.character(backup))
        self$do_operation("restore", body=list(value=backup), encode="json", http_verb="POST") 
    },

    do_operation=function(op="", ..., options=list())
    {
        url <- self$url
        url$path <- construct_path("secrets", op)
        url$query <- options
        call_vault_url(self$token, url, ...)
    },

    print=function(...)
    {
        url <- self$url
        url$path <- "secrets"
        cat("<key vault endpoint '", httr::build_url(url), "'>\n", sep="")
        invisible(self)
    }
))
