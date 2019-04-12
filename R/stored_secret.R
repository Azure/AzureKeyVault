stored_secret <- R6::R6Class("stored_secret", inherit=stored_object,

public=list(

    type="secrets",

    id=NULL,
    kid=NULL,
    value=NULL,
    contentType=NULL,

    list_versions=function()
    {
        lst <- lapply(get_vault_paged_list(self$do_operation("versions", version=NULL), self$token), function(props)
        {
            content_type <- if(!is_empty(props$contentType))
                props$contentType
            else NA
            attr <- props$attributes
            data.frame(
                version=basename(props$id),
                content_type=content_type,
                created=int_to_date(attr$created),
                updated=int_to_date(attr$updated),
                expiry=int_to_date(attr$exp),
                not_before=int_to_date(attr$nbf),
                stringsAsFactors=FALSE
            )
        })
        do.call(rbind, lst)
    }
))
