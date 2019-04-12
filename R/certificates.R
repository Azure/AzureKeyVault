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
                    key_properties=vault_key_properties(),
                    attributes=vault_object_attrs(),
                    key_ops=NULL,
                    key_exportable=TRUE, reuse_key=FALSE, ..., wait=TRUE)
    {
        keyprops <- c(key_properties, reuse_key=reuse_key, exportable=key_exportable)

        policy <- list(
            key_props=keyprops,
            issuer=issuer,
            lifetime_actions=actions,
            secret_props=secret,
            x509_props=x509
        )

        body <- list(policy=policy, attributes=attributes, tags=list(...))

        op <- construct_path(name, "create")
        self$do_operation(op, body=body, encode="json", http_verb="POST")
        cert <- self$get(name)

        if(!wait)
            message("Certificate creation started. Call the sync() method to update status.")
        else while(is.null(cert$cer))
        {
            Sys.sleep(5)
            cert <- self$get(name)
        }
        cert
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
                    key_properties=vault_key_properties(),
                    attributes=vault_object_attrs(),
                    key_ops=NULL,
                    key_exportable=TRUE, reuse_key=FALSE, ...)
    {
        keyprops <- c(key_properties, reuse_key=reuse_key, exportable=key_exportable)

        policy <- list(
            key_props=keyprops,
            issuer=issuer,
            lifetime_actions=actions,
            secret_props=secret,
            x509_props=x509
        )

        body <- list(value=value, pwd=pwd, policy=policy, attributes=attributes, tags=list(...))
        self$do_operation(name, body=body, encode="json", http_verb="PUT")
        self$get(name)
    },

    get_contacts=function()
    {
        self$do_operation("contacts")
    },

    set_contacts=function(email, name, phone)
    {
        df <- data.frame(email, name, phone, stringsAsFactors=FALSE)
        self$do_operation("contacts", body=list(contacts=df), encode="json", http_verb="PUT")
    },

    delete_contacts=function()
    {
        self$do_operation("contacts", http_verb="DELETE")
    },

    get_policy=function(name)
    {
        op <- construct_path(name, "policy")
        self$do_operation(op)
    },

    set_policy=function(name, policy)
    {
        body <- list(policy)
        op <- construct_path(name, "policy")
        self$do_operation(op, body=body, encode="json", http_verb="PATCH")
    },

    do_operation=function(op="", ..., options=list())
    {
        url <- self$url
        url$path <- construct_path("certificates", op)
        url$query <- options
        call_vault_url(self$token, url, ...)
    }
))
