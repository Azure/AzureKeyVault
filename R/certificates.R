vault_certificates <- R6::R6Class("vault_certificates", 

public=list(

    token=NULL,
    url=NULL,

    initialize=function(token, url)
    {
        self$token <- token
        self$url <- url
    },

    create=function(name, type=c("RSA", "RSA-HSM", "EC", "EC-HSM"), ec_curve=NULL, rsa_key_size=NULL, key_ops=NULL,
                    exportable=TRUE, reuse_key=FALSE, issuer=list(), secret=list(), x509=list(), actions=list(),
                    enabled=NULL, expiry_date=NULL, activation_date=NULL, recovery_level=NULL, ...)
    {
        attribs <- list(
            enabled=enabled,
            nbf=make_vault_date(activation_date),
            exp=make_vault_date(expiry_date),
            recoveryLevel=recovery_level
        )
        attribs <- attribs[!sapply(attribs, is_empty)]

        keyprops <- list(kty=match.arg(type))
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
        self$do_operation("backup", http_verb="POST")
    },

    restore=function(name, backup)
    {
        stopifnot(is.character(backup))
        self$do_operation("restore", body=list(value=backup), encode="json", http_verb="POST") 
    },

    import=function(name, value, hardware=FALSE,
                    enabled=NULL, expiry_date=NULL, activation_date=NULL, recovery_level=NULL, ...)
    {
        attribs <- list(
            enabled=enabled,
            nbf=make_vault_date(activation_date),
            exp=make_vault_date(expiry_date),
            recoveryLevel=recovery_level
        )
        attribs <- attribs[!sapply(attribs, is_empty)]

        body <- list(key=value, key=type, hsm=hardware, attributes=attribs, tags=list(...))
        self$do_operation(name, body=body, encode="json", http_verb="PUT")
    },

    do_operation=function(op="", ..., options=list(),
                          api_version=getOption("azure_keyvault_api_version"))
    {
        url <- self$url
        url$path <- construct_path("certificates", op)
        url$query <- utils::modifyList(list(`api-version`=api_version), options)

        call_vault_url(self$token, url, ...)
    }
))
