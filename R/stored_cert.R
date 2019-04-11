stored_cert <- R6::R6Class("stored_cert",

public=list(

    token=NULL,
    url=NULL,
    name=NULL,
    version=NULL,

    id=NULL,
    sid=NULL,
    kid=NULL,
    cer=NULL,
    x5t=NULL,
    contentType=NULL,
    pending=NULL,
    policy=NULL,

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

        if(is.null(self$version))
            self$version <- basename(self$id)
    },

    do_operation=function(op="", ..., options=list())
    {
        url <- self$url
        url$path <- construct_path("certificates", self$name, self$version, op)
        url$query <- options
        call_vault_url(self$token, url, ...)
    }
))
