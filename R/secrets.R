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
            self$do_operation(name, http_verb="DELETE")
    },

    list_all=function()
    {
        lst <- lapply(get_vault_paged_list(self$do_operation(), self$token), function(props)
        {
            name <- basename(props$id)
            secret <- call_vault_url(self$token, props$id)
            stored_secret$new(self$token, self$url, name, NULL, secret)
        })
        named_list(lst)
    },

    list_versions=function(name)
    {
        op <- construct_path(name, "versions")
        lst <- lapply(get_vault_paged_list(self$do_operation(op), self$token), function(props)
        {
            secret <- call_vault_url(self$token, props$id)
            stored_secret$new(self$token, self$url, name, NULL, secret)
        })
        names(lst) <- sapply(lst, function(x) file.path(x$name, x$version))
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

    do_operation=function(op="", ..., options=list())
    {
        url <- self$url
        url$path <- construct_path("secrets", op)
        url$query <- options
        call_vault_url(self$token, url, ...)
    }
))
