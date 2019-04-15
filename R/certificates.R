vault_certificates <- R6::R6Class("vault_certificates", 

public=list(

    token=NULL,
    url=NULL,

    initialize=function(token, url)
    {
        self$token <- token
        self$url <- url
    },

    create=function(name, subject, x509=cert_x509_properties(), issuer=cert_issuer_properties(),
                    key=cert_key_properties(),
                    secret_type=c("pem", "pkcs12"),
                    actions=cert_expiry_actions(),
                    attributes=vault_object_attrs(),
                    ..., wait=TRUE)
    {
        secret_type <- if(match.arg(secret_type) == "pem")
            "application/x-pem-file"
        else "application/x-pkcs12"

        policy <- list(
            issuer=issuer,
            key_props=key,
            secret_props=list(contentType=secret_type),
            x509_props=c(subject=subject, x509),
            lifetime_actions=actions,
            attributes=attributes
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

    list=function()
    {
        sapply(get_vault_paged_list(self$do_operation(), self$token),
            function(props) basename(props$id))
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

    import=function(name, value, pwd=NULL,
                    attributes=vault_object_attrs(),
                    ..., wait=TRUE)
    {
        if(is.character(value) && length(value) == 1 && file.exists(value))
            value <- readBin(value, "raw", file.info(value)$size)

        body <- list(value=value, pwd=pwd, attributes=attributes, tags=list(...))

        self$do_operation(construct_path(name, "import"), body=body, encode="json", http_verb="POST")
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

    do_operation=function(op="", ..., options=list())
    {
        url <- self$url
        url$path <- construct_path("certificates", op)
        url$query <- options
        call_vault_url(self$token, url, ...)
    }
))
