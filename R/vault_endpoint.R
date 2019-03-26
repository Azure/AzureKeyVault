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
        self$call_endpoint("keys")
    },

    create_secret=function()
    {},

    get_secret=function()
    {},

    delete_secret=function()
    {},

    list_secrets=function()
    {
        self$call_endpoint("secrets")
    },

    create_certificate=function()
    {},

    get_certificate=function()
    {},

    delete_certificate=function()
    {},

    list_certificates=function()
    {
        self$call_endpoint("certificates")
    },

    call_endpoint=function(op="", ..., options=list(),
                              api_version=getOption("azure_keyvault_api_version"),
                              http_verb=c("GET", "DELETE", "PUT", "POST", "HEAD", "PATCH"),
                              http_status_handler=c("stop", "warn", "message", "pass"))
    {
        url <- self$url
        url$path <- op
        url$query <- utils::modifyList(list(`api-version`=api_version), options)

        headers <- process_headers(self$token, self$url$hostname, ...)
        res <- httr::VERB(match.arg(http_verb), url, headers, ...)
        process_response(res, match.arg(http_status_handler))
    }
))
