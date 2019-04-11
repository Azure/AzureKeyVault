stored_secret <- R6::R6Class("stored_secret", inherit=stored_object,

public=list(

    type="secrets",

    id=NULL,
    kid=NULL,
    value=NULL,
    contentType=NULL,

    initialize=function(...)
    {
        super$initialize(...)
        if(is.null(self$version))
            self$version <- basename(self$id)
    }
))
