#' @export
vault_endpoint <- R6::R6Class("vault_endpoint", public=list(
    
    token=NULL,
    tenant=NULL,
    url=NULL,

    initialize=function(url, token)
    {
        self$url <- url
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
    {},

    create_secret=function()
    {},

    get_secret=function()
    {},

    delete_secret=function()
    {},

    list_secrets=function()
    {},

    create_certificate=function()
    {},

    get_certificate=function()
    {},

    delete_certificate=function()
    {},

    list_certificates=function()
    {}
),

private=list(

    vault_op=function()
    {}
))
