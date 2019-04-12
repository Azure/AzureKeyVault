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

    initialize=function(...)
    {
        super$initialize(...)
        if(is.null(self$version))
            self$version <- basename(self$id)
    },

    sync=function()
    {
        pending <- call_vault_url(self$token, self$pending$id)
        if(pending$status == "completed" && !is_empty(pending$target))
        {
            props <- call_vault_url(self$token, pending$target)
            self$initialize(self$token, self$url, self$name, NULL, props)
        }
        self
    }
))
