stored_account <- R6::R6Class("stored_account", inherit=stored_object,

public=list(

    type="storage",

    id=NULL,
    resourceId=NULL,
    activeKeyName=NULL,
    autoRegenerateKey=NULL,
    regenerationPeriod=NULL,

    regenerate_key=function(name, key_name)
    {
        self$do_operation("regeneratekey", body=list(keyName=key_name), http_verb="POST")
    },

    create_sas_definition=function(sas_name, sas_template, validity_period, sas_type="account",
                                   enabled=TRUE, recovery_level=NULL, ...)
    {
        attribs <- list(
            enabled=enabled,
            recoveryLevel=recovery_level
        )
        attribs <- attribs[!sapply(attribs, is_empty)]

        body <- list(
            sasType=sas_type,
            templateUri=sas_template,
            validityPeriod=validity_period,
            attributes=attribs,
            tags=list(...)
        )

        op <- construct_path("sas", sas_name)
        self$do_operation(op, body=body, encode="json", http_verb="PUT")
    },

    delete_sas_definition=function(sas_name, confirm=TRUE)
    {
        if(delete_confirmed(confirm, sas_name, "SAS definition"))
        {
            op <- construct_path("sas", sas_name)
            self$do_operation(op, http_verb="DELETE")
        }
    },

    get_sas_definition=function(sas_name)
    {
        op <- construct_path("sas", sas_name)
        self$do_operation(op)
    },

    list_sas_definitions=function()
    {
        get_vault_paged_list(self$do_operation("sas"), self$token)
    },

    show_sas=function(sas_name)
    {
        secret_url <- self$get_sas_definition(sas_name)$sid
        call_vault_url(self$token, secret_url)$value
    }
))
