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

    delete=function(confirm=TRUE)
    {
        type <- if(self$type == "storage")
            "storage account"
        else sub("s$", "", self$type)

        if(delete_confirmed(confirm, self$name, type))
            self$do_operation(version=NULL, http_verb="DELETE")
    },

    update_attributes=function(attributes=vault_object_attrs(), ...)
    {
        body <- list(attributes=attributes, ...)
        props <- self$do_operation(body=body, encode="json", http_verb="PATCH")
        self$initialize(self$token, self$url, self$name, self$version, props)
        self
    },

    set_version=function(version=NULL)
    {
        props <- self$do_operation(version=version)
        self$initialize(self$token, self$url, self$name, version, props)
        self
    },

    do_operation=function(op="", ..., version=self$version, options=list())
    {
        url <- self$url
        url$path <- construct_path(self$type, self$name, version, op)
        url$query <- options
        call_vault_url(self$token, url, ...)
    },

    print=function(...)
    {
        cat("<vault stored object '", self$name, "'>\n")
        invisible(self)
    }
))


