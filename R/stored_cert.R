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
    }
))
