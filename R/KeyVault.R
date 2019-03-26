#' @export
KeyVault <- R6::R6Class("key_vault", public=list(
    
    token=NULL,
    uri=NULL,

    initialize=function(token)
    {
        self$token <- token

        if(is_azure_token(token) || inherits(token, "Token2.0"))
            token <- token$credentials$access_token
        else if(!is.character(token))
            stop("Must supply a valid token object", call.=FALSE)

        self$uri <- decode_jwt(token)$payload$aud
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
