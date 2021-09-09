#' Azure Key Vault endpoint class
#'
#' Class representing the client endpoint for a key vault, exposing methods for working with it. Use the `[key_vault]` function to instantiate new objects of this class.
#'
#' @docType class
#' @section Fields:
#' - `keys`: A sub-object for working with encryption keys stored in the vault. See [keys].
#' - `secrets`: A sub-object for working with secrets stored in the vault. See [secrets].
#' - `certificates`: A sub-object for working with certificates stored in the vault. See [certificates].
#' - `storage`: A sub-object for working with storage accounts managed by the vault. See [storage].
#'
#' @seealso
#' [key_vault], [keys], [secrets], [certificates], [storage]
#'
#' [Azure Key Vault documentation](https://docs.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://docs.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' key_vault("mykeyvault")
#' key_vault("https://mykeyvault.vault.azure.net")
#'
#' # authenticating as a service principal
#' key_vault("mykeyvault", tenant="myaadtenant", app="app_id", password="password")
#'
#' # authenticating with an existing token
#' token <- AzureAuth::get_azure_token("https://vault.azure.net", "myaadtenant",
#'                                     app="app_id", password="password")
#' key_vault("mykeyvault", token=token)
#'
#' }
#' @export
AzureKeyVault <- R6::R6Class("AzureKeyVault", public=list(

    token=NULL,
    url=NULL,

    keys=NULL,
    secrets=NULL,
    certificates=NULL,
    storage=NULL,

    initialize=function(token, url)
    {
        self$token <- token
        self$url <- url

        self$keys <- vault_keys$new(self$token, self$url)
        self$secrets <- vault_secrets$new(self$token, self$url)
        self$certificates <- vault_certificates$new(self$token, self$url)
        self$storage <- vault_storage_accounts$new(self$token, self$url)
    },

    call_endpoint=function(op="", ..., options=list())
    {
        url <- self$url
        url$path <- op
        url$query <- options
        call_vault_url(self$token, url, ...)
    },

    print=function(...)
    {
        cat("Azure Key Vault '", httr::build_url(self$url), "'\n", sep="")
        cat("<Authentication>\n")
        if(is_azure_token(self$token))
        {
            fmt_token <- gsub("\n  ", "\n    ", AzureAuth::format_auth_header(self$token))
            cat(" ", fmt_token)
        }
        else cat("  <string>\n")
        invisible(self)
    }
))


#' Azure Key Vault client
#'
#' @param url The location of the vault. This can be a full URL, or the vault name alone; in the latter case, the `domain` argument is appended to obtain the URL.
#' @param tenant,app, Authentication arguments that will be passed to [`AzureAuth::get_azure_token`]. The default is to authenticate interactively.
#' @param domain The domain of the vault; for the public Azure cloud, this is `vault.azure.net`. Also the resource for OAuth authentication.
#' @param as_managed_identity Whether to authenticate as a managed identity. Use this if your R session is taking place inside an Azure VM or container that has a system- or user-assigned managed identity assigned to it.
#' @param token An OAuth token obtained via [`AzureAuth::get_azure_token`]. If provided, this overrides the other authentication arguments.
#' @param ... Further arguments that will be passed to either `get_azure_token or [`AzureAuth::get_managed_token`], depending on whether `as_managed_identity` is TRUE.
#'
#' @details
#' This function creates a new Key Vault client object. It includes the following component objects for working with data in the vault:
#'
#' - `keys`: A sub-object for working with encryption keys stored in the vault. See [keys].
#' - `secrets`: A sub-object for working with secrets stored in the vault. See [secrets].
#' - `certificates`: A sub-object for working with certificates stored in the vault. See [certificates].
#' - `storage`: A sub-object for working with storage accounts managed by the vault. See [storage].
#'
#' @seealso
#' [`keys`], [`secrets`], [`certificates`], [`storage`]
#'
#' [Azure Key Vault documentation](https://docs.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://docs.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' key_vault("mykeyvault")
#' key_vault("https://mykeyvault.vault.azure.net")
#'
#' # authenticating as a service principal
#' key_vault("mykeyvault", tenant="myaadtenant", app="app_id", password="password")
#'
#' # authenticating with an existing token
#' token <- AzureAuth::get_azure_token("https://vault.azure.net", "myaadtenant",
#'                                     app="app_id", password="password")
#' key_vault("mykeyvault", token=token)
#'
#' # authenticating with a system-assigned managed identity
#' key_vault("mykeyvault", as_managed_identity=TRUE)
#'
#' # authenticating with a user-assigned managed identity:
#' # - supply one of the identity's object ID, client ID or resource ID
#' key_vault("mykeyvault", as_managed_identity=TRUE,
#'     token_args=list(mi_res_id="/subscriptions/xxxx/resourceGroups/resgrpname/..."))
#'
#' }
#' @export
key_vault <- function(url, tenant="common", app=.az_cli_app_id, ..., domain="vault.azure.net",
                      as_managed_identity=FALSE, token=NULL)
{
    if(!is_url(url))
        url <- sprintf("https://%s.%s", url, domain)

    # "https://vault.azure.net/" (with trailing slash) will fail
    if(is.null(token))
    {
        token <- if(as_managed_identity)
            get_managed_token(sprintf("https://%s", domain), ...)
        else get_azure_token(sprintf("https://%s", domain), tenant=tenant, app=app, ...)
    }

    AzureKeyVault$new(token, httr::parse_url(url))
}

