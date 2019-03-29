#' @export
key_vault <- R6::R6Class("key_vault", public=list(
    
    token=NULL,
    url=NULL,

    keys=NULL,
    secrets=NULL,
    certificates=NULL,
    storage_accounts=NULL,

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
        #self$storage <- vault_storage_accounts$new(self$token, self$url)
    },

    call_endpoint=function(op="", ..., options=list(),
                           api_version=getOption("azure_keyvault_api_version"))
    {
        url <- self$url
        url$path <- op
        url$query <- utils::modifyList(list(`api-version`=api_version), options)

        call_vault_url(self$token, url, ...)
    }
))
