stored_object <- R6::R6Class("stored_object",

public=list(

    token=NULL,
    url=NULL,
    name=NULL,
    version=NULL,

    attributes=NULL,
    managed=NULL,
    tags=NULL,

    initialize=function(token, url, name, version, properties)
    {
        self$token <- token
        self$url <- url
        self$name <- name
        self$version <- version

        lapply(names(properties), function(n)
        {
            if(exists(n, self))
                self[[n]] <- properties[[n]]
            else warning("Unexpected property: ", n)
        })
    },

    update_attributes=function(attributes=vault_object_attrs(), ...)
    {
        body <- list(attributes=attributes, ...)
        self$do_operation(body=body, encode="json", http_verb="PATCH")
    },

    do_operation=function(op="", ..., options=list())
    {
        url <- self$url
        url$path <- construct_path(self$type, self$name, self$version, op)
        url$query <- options
        call_vault_url(self$token, url, ...)
    }
))


