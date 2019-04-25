#' Azure Key Vault endpoint class
#'
#' Class representing the client endpoint for a key vault, exposing methods for working with it.
#'
#' @docType class
#' @section Fields:
#' - `keys`: A sub-object for working with encryption keys stored in the vault. See [keys].
#' - `secrets`: A sub-object for working with secrets stored in the vault. See [secrets].
#' - `certificates`: A sub-object for working with certificates stored in the vault. See [certificates].
#' - `storage`: A sub-object for working with storage accounts managed by the vault. See [storage].
#'
#' @section Methods:
#' This class provides one method, for initialization:
#' ```
#' new(url, tenant = "common", app = .az_cli_app_id, ...,
#'     domain = "vault.azure.net", token = NULL)
#' ```
#' The arguments are as follows:
#' - `url`: The location of the vault. This can be a full URL, or the vault name alone; in the latter case, the `domain` argument is appended to obtain the URL.
#' - `tenant, app, ...`: Authentication arguments that will be passed to [AzureAuth::get_azure_token]. The default is to authenticate interactively.
#' - `domain`: The domain of the vault; for the public Azure cloud, this is `vault.azure.net`. Also the resource for OAuth authentication.
#' - `token`: An OAuth token obtained via [AzureAuth::get_azure_token]. If provided, this overrides the other authentication arguments.
#'
#' To work with objects stored in the key vault, use the methods provided by one of the sub-objects listed in 'Fields'.
#'
#' @seealso
#' [az_key_vault], [keys], [secrets], [certificates], [storage]
#'
#' [Azure Key Vault documentation](https://docs.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://docs.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' key_vault$new("mykeyvault")
#' key_vault$new("https://mykeyvault.vault.azure.net")
#'
#' # authenticating as a service principal
#' key_vault$new("mykeyvault", tenant="myaadtenant", app="app_id", password="password")
#'
#' # authenticating with an existing token
#' token <- AzureAuth::get_azure_token("https://vault.azure.net", "myaadtenant",
#'                                     app="app_id", password="password")
#' key_vault$new("mykeyvault", token=token)
#'
#' }
#' @export
key_vault <- R6::R6Class("key_vault", public=list(
    
    token=NULL,
    url=NULL,

    keys=NULL,
    secrets=NULL,
    certificates=NULL,
    storage=NULL,

    initialize=function(url, tenant="common", app=.az_cli_app_id, ..., domain="vault.azure.net", token=NULL)
    {
        if(!is_url(url))
            url <- sprintf("https://%s.%s", url, domain)

        # "https://vault.azure.net/" (with trailing slash) will fail
        if(is.null(token))
            token <- get_azure_token(sprintf("https://%s", domain), tenant=tenant, app=app, ...)

        self$url <- httr::parse_url(url)
        self$token <- token

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
        cat("<key vault '", httr::build_url(self$url), "'>\n", sep="")
        invisible(self)
    }
))
