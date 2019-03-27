#' @export
vault_endpoint <- R6::R6Class("vault_endpoint", public=list(
    
    token=NULL,
    url=NULL,
    tenant=NULL,

    keys=NULL,
    secrets=NULL,
    certificates=NULL,
    storage_accounts=NULL,

    initialize=function(url, tenant, app, password, ..., token=NULL)
    {
        self$url <- httr::parse_url(url)
        self$tenant <- tenant

        # "https://vault.azure.net/" (with trailing slash) will fail
        if(is.null(token))
            token <- get_azure_token("https://vault.azure.net", tenant=tenant, app=app, password=password, ...)

        self$token <- token

        #private$keys <- vault_keys$new(self$token, self$url)
        self$secrets <- vault_secrets$new(self$token, self$url)
        #private$certificates <- vault_certificates$new(self$token, self$url)
        #private$storage_accounts <- vault_storage_accounts$new(self$token, self$url)
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
