#' @export
vault_endpoint <- R6::R6Class("vault_endpoint", public=list(
    
    token=NULL,
    tenant=NULL,
    url=NULL,

    initialize=function(url, tenant, app, password, ..., token=NULL)
    {
        self$url <- httr::parse_url(url)

        if(is.null(token))
            token <- get_azure_token("https://vault.azure.net", tenant=tenant, app=app, password=password, ...)

        self$token <- token

        if(is_azure_token(token) || inherits(token, "Token2.0"))
            token <- token$credentials$access_token
        else if(!is.character(token))
            stop("Must supply a valid token object", call.=FALSE)

        self$tenant <- AzureAuth::decode_jwt(token)$payload$tid
    },

    create_key=function()
    {},

    get_key=function()
    {},

    delete_key=function()
    {},

    list_keys=function()
    {
        lst <- self$call_endpoint("keys")
        private$get_paged_list(lst)
    },

    create_secret=function()
    {},

    get_secret=function(name, version, which=NULL)
    {},

    delete_secret=function()
    {},

    list_secrets=function()
    {
        lst <- self$call_endpoint("secrets")
        private$get_paged_list(lst)
    },

    create_certificate=function()
    {},

    get_certificate=function()
    {},

    delete_certificate=function()
    {},

    list_certificates=function()
    {
        lst <- self$call_endpoint("certificates")
        private$get_paged_list(lst)
    },

    call_endpoint=function(op="", ..., options=list(),
                           api_version=getOption("azure_keyvault_api_version"))
    {
        url <- self$url
        url$path <- op
        url$query <- utils::modifyList(list(`api-version`=api_version), options)

        call_vault_url(self$token, url, ...)
    }
),

private=list(

    get_paged_list=function(lst, next_link_name="nextLink", value_name="value")
    {
        res <- lst[[value_name]]
        while(!is_empty(lst[[next_link_name]]))
        {
            lst <- call_vault_url(self$token, lst[[next_link_name]])
            res <- c(res, lst[[value_name]])
        }
        res
    }
))
