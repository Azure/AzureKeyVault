vault_keys <- R6::R6Class("vault_keys", 

public=list(

    token=NULL,
    url=NULL,

    initialize=function(token, url)
    {
        self$token <- token
        self$url <- url
    },

    create=function(name, type=c("RSA", "RSA-HSM", "EC", "EC-HSM"), ec_curve=NULL, rsa_key_size=NULL, key_ops=NULL,
                    enabled=NULL, expiry_date=NULL, activation_date=NULL, recovery_level=NULL, ...)
    {
        type <- match.arg(type)

        attribs <- list(
            enabled=enabled,
            nbf=make_vault_date(activation_date),
            exp=make_vault_date(expiry_date),
            recoveryLevel=recovery_level
        )
        attribs <- attribs[!sapply(attribs, is_empty)]

        body <- list(kty=type, attributes=attribs, key_ops=key_ops, tags=list(...))

        if(type %in% c("RSA", "RSA-HSM"))
            body$key_size=rsa_key_size
        else if(type %in% c("EC", "EC-HSM"))
            body$crv <- ec_curve

        op <- construct_path(name, "create")
        self$do_operation(op, body=body, encode="json", http_verb="POST")
    },

    show=function(name, version=NULL)
    {
        op <- construct_path(name, version)
        self$do_operation(op)
    },

    delete=function(name, confirm=TRUE)
    {
        if(delete_confirmed(confirm, name, "key"))
            self$do_operation(name, http_verb="DELETE")
    },

    list_all=function()
    {
        lst <- get_vault_paged_list(self$do_operation(), self$token)
        names(lst) <- sapply(lst, function(x) basename(x$kid))
        lst
    },

    list_versions=function(name)
    {
        op <- construct_path(name, "versions")
        lst <- get_vault_paged_list(self$do_operation(op), self$token)
        names(lst) <- sapply(lst, function(x) basename(x$kid))
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
    },

    do_operation=function(op="", ..., options=list(),
                          api_version=getOption("azure_keyvault_api_version"))
    {
        url <- self$url
        url$path <- construct_path("keys", op)
        url$query <- utils::modifyList(list(`api-version`=api_version), options)

        call_vault_url(self$token, url, ...)
    }
))
