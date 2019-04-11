vault_certificates <- R6::R6Class("vault_certificates", 

public=list(

    token=NULL,
    url=NULL,

    initialize=function(token, url)
    {
        self$token <- token
        self$url <- url
    },

    create=function(name, issuer=list(), secret=list(), x509=list(), actions=list(),
                    enabled=NULL, expiry_date=NULL, activation_date=NULL, recovery_level=NULL,
                    key_type=c("RSA", "RSA-HSM", "EC", "EC-HSM"), ec_curve=NULL, rsa_key_size=NULL, key_ops=NULL,
                    key_exportable=TRUE, reuse_key=FALSE, ...)
    {
        attribs <- list(
            enabled=enabled,
            nbf=make_vault_date(activation_date),
            exp=make_vault_date(expiry_date),
            recoveryLevel=recovery_level
        )
        attribs <- attribs[!sapply(attribs, is_empty)]

        keyprops <- list(kty=match.arg(key_type), reuse_key=reuse_key, exportable=key_exportable)
        if(keyprops$kty %in% c("RSA", "RSA-HSM"))
            keyprops$key_size=rsa_key_size
        else if(keyprops$kty %in% c("EC", "EC-HSM"))
            keyprops$crv <- ec_curve

        policy <- list(
            key_props=keyprops,
            issuer=issuer,
            lifetime_actions=actions,
            secret_props=secret,
            x509_props=x509
        )

        body <- list(policy=policy, attributes=attribs, tags=list(...))

        op <- construct_path(name, "create")
        self$do_operation(op, body=body, encode="json", http_verb="POST")
        self$get(name)
    },

    get=function(name, version=NULL)
    {
        op <- construct_path(name, version)
        stored_cert$new(self$token, self$url, name, version, self$do_operation(op))
    },

    delete=function(name, confirm=TRUE)
    {
        if(delete_confirmed(confirm, name, "certificate"))
            self$do_operation(name, http_verb="DELETE")
    },

    list_all=function()
    {
        lst <- lapply(get_vault_paged_list(self$do_operation(), self$token), function(props)
        {
            name <- basename(props$id)
            cert <- call_vault_url(self$token, props$id)
            stored_cert$new(self$token, self$url, name, NULL, cert)
        })
        named_list(lst)
    },

    list_versions=function(name)
    {
        op <- construct_path(name, "versions")
        lst <- lapply(get_vault_paged_list(self$do_operation(op), self$token), function(props)
        {
            cert <- call_vault_url(self$token, props$id)
            stored_cert$new(self$token, self$url, name, NULL, cert)
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

    import=function(name, value, pwd=NULL, issuer=list(), secret=list(), x509=list(), actions=list(),
                    enabled=NULL, expiry_date=NULL, activation_date=NULL, recovery_level=NULL,
                    key_type=c("RSA", "RSA-HSM", "EC", "EC-HSM"), ec_curve=NULL, rsa_key_size=NULL, key_ops=NULL,
                    key_exportable=TRUE, reuse_key=FALSE, ...)
    {
        attribs <- list(
            enabled=enabled,
            nbf=make_vault_date(activation_date),
            exp=make_vault_date(expiry_date),
            recoveryLevel=recovery_level
        )
        attribs <- attribs[!sapply(attribs, is_empty)]

        keyprops <- list(kty=match.arg(key_type), reuse_key=reuse_key, exportable=key_exportable)
        if(keyprops$kty %in% c("RSA", "RSA-HSM"))
            keyprops$key_size=rsa_key_size
        else if(keyprops$kty %in% c("EC", "EC-HSM"))
            keyprops$crv <- ec_curve

        policy <- list(
            key_props=keyprops,
            issuer=issuer,
            lifetime_actions=actions,
            secret_props=secret,
            x509_props=x509
        )

        body <- list(value=value, pwd=pwd, policy=policy, attributes=attribs, tags=list(...))
        self$do_operation(name, body=body, encode="json", http_verb="PUT")
        self$get(name)
    },

    do_operation=function(op="", ..., options=list())
    {
        url <- self$url
        url$path <- construct_path("certificates", op)
        url$query <- options
        call_vault_url(self$token, url, ...)
    }
))
