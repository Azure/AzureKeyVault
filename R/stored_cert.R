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

    set_policy=function(policy)
    {
        body <- list(policy=policy)
        op <- construct_path(self$name, "policy")
        self$do_operation(op, body=body, encode="json", version=NULL, http_verb="PATCH")
    }
))
