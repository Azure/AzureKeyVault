vault_keys <- R6::R6Class("vault_keys", 

public=list(

    token=NULL,
    url=NULL,

    initialize=function(token, url)
    {
        self$token <- token
        self$url <- url
    },

    create=function(name, properties=key_properties(), key_ops=NULL,
                    attributes=vault_object_attrs(), ...)
    {
        body <- c(properties, list(attributes=attributes, key_ops=key_ops, tags=list(...)))

        op <- construct_path(name, "create")
        self$do_operation(op, body=body, encode="json", http_verb="POST")
        self$get(name)
    },

    get=function(name)
    {
        stored_key$new(self$token, self$url, name, NULL, self$do_operation(name))
    },

    delete=function(name, confirm=TRUE)
    {
        if(delete_confirmed(confirm, name, "key"))
            self$do_operation(name, http_verb="DELETE")
    },

    list=function()
    {
        sapply(get_vault_paged_list(self$do_operation(), self$token),
            function(props) basename(props$kid))
    },

    backup=function(name)
    {
        op <- construct_path(name, "backup")
        self$do_operation(op, http_verb="POST")$value
    },

    restore=function(backup)
    {
        stopifnot(is.character(backup))
        op <- construct_path(name, "restore")
        self$do_operation(op, body=list(value=backup), encode="json", http_verb="POST") 
    },

    import=function(name, key, hardware=FALSE,
                    enabled=NULL, expiry_date=NULL, activation_date=NULL, recovery_level=NULL, ...)
    {
        # support importing keys from openssl package, or as json text
        if(inherits(key, "key"))
            key <- jsonlite::fromJSON(jose::write_jwk(key))
        else if(is.character(key) && jsonlite::validate(key))
            key <- jsonlite::fromJSON(key)

        attribs <- list(
            enabled=enabled,
            nbf=make_vault_date(activation_date),
            exp=make_vault_date(expiry_date),
            recoveryLevel=recovery_level
        )
        attribs <- attribs[!sapply(attribs, is_empty)]

        body <- list(key=key, hsm=hardware, attributes=attribs, tags=list(...))
        self$do_operation(name, body=body, encode="json", http_verb="PUT")
        self$get(name)
    },

    do_operation=function(op="", ..., options=list())
    {
        url <- self$url
        url$path <- construct_path("keys", op)
        url$query <- options
        call_vault_url(self$token, url, ...)
    }
))

