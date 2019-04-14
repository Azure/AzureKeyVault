stored_cert <- R6::R6Class("stored_cert", inherit=stored_object,

public=list(

    type="certificates",

    id=NULL,
    sid=NULL,
    kid=NULL,
    cer=NULL,
    x5t=NULL,
    contentType=NULL,
    pending=NULL,
    policy=NULL,

    sync=function()
    {
        pending <- call_vault_url(self$token, self$pending$id)
        if(pending$status == "completed" && !is_empty(pending$target))
        {
            props <- call_vault_url(self$token, pending$target)
            self$initialize(self$token, self$url, self$name, NULL, props)
        }
        self
    },

    list_versions=function()
    {
        lst <- lapply(get_vault_paged_list(self$do_operation("versions", version=NULL), self$token), function(props)
        {
            attr <- props$attributes
            data.frame(
                version=basename(props$id),
                thumbprint=props$x5t,
                created=int_to_date(attr$created),
                updated=int_to_date(attr$updated),
                expiry=int_to_date(attr$exp),
                not_before=int_to_date(attr$nbf),
                stringsAsFactors=FALSE
            )
        })
        do.call(rbind, lst)
    },

    get_policy=function()
    {
        op <- construct_path(self$name, "policy")
        self$do_operation(op, version=NULL)
    },

    set_policy=function(subject=NULL, x509=NULL, issuer=NULL,
                        key=NULL, secret_type=NULL, actions=NULL,
                        attributes=NULL, wait=TRUE)
    {
        if(!is.null(secret_type))
        {
            secret_type <- if(secret_type == "pem")
                "application/x-pem-file"
            else "application/x-pkcs12"
        }

        policy <- list(
            issuer=issuer,
            key_props=key,
            secret_props=list(contentType=secret_type),
            x509_props=c(subject=subject, x509),
            lifetime_actions=actions
        )

        body <- list(policy=compact(policy), attributes=attributes)

        op <- construct_path(self$name, "policy")
        pol <- self$do_operation(op, body=body, encode="json", version=NULL, http_verb="PATCH")
        self$policy <- pol
        pol
    }
))
