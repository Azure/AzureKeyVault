vault_secrets <- R6::R6Class("vault_secrets", 

public=list(

    token=NULL,
    url=NULL,

    initialize=function(token, url)
    {
        self$token <- token
        self$url <- url
    },

    set=function(name, value, content_type=NULL, enabled=NULL, expiry_date=NULL, activation_date=NULL,
                 recovery_level=NULL, ...)
    {
        attribs <- list(
            enabled=enabled,
            nbf=make_vault_date(activation_date),
            exp=make_vault_date(expiry_date),
            recoveryLevel=recovery_level
        )
        attribs <- attribs[!sapply(attribs, is_empty)]

        body <- list(value=value, contentType=content_type, attributes=attribs, tags=list(...))

        self$do_operation(name, body=body, encode="json", http_verb="PUT")
    },

    show=function(name, version=NULL)
    {
        op <- construct_path(name, version)
        self$do_operation(op)
    },

    delete=function(name, confirm=TRUE)
    {
        if(delete_confirmed(confirm, name, "secret"))
            self$do_operation(name, http_verb="DELETE")
    },

    list_all=function()
    {
        lst <- get_vault_paged_list(self$do_operation(), self$token)
        names(lst) <- sapply(lst, function(x) basename(x$id))
        lst
    },

    versions_of=function(name)
    {
        op <- construct_path(name, "versions")
        lst <- get_vault_paged_list(self$do_operation(op), self$token)
        names(lst) <- sapply(lst, function(x) basename(x$id))
        lst
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

    do_operation=function(op="", ..., options=list(),
                          api_version=getOption("azure_keyvault_api_version"))
    {
        url <- self$url
        url$path <- construct_path("secrets", op)
        url$query <- utils::modifyList(list(`api-version`=api_version), options)

        call_vault_url(self$token, url, ...)
    }
))
