vault_storage_accounts <- R6::R6Class("vault_storage_accounts", 

public=list(

    token=NULL,
    url=NULL,

    initialize=function(token, url)
    {
        self$token <- token
        self$url <- url
    },

    add=function(name, storage_account, key_name, regen_key=TRUE, regen_period=30,
                 enabled=NULL, recovery_level=NULL, ...)
    {
        if(is_resource(storage_account))
            storage_account <- storage_account$id

        attribs <- list(
            enabled=enabled,
            recoveryLevel=recovery_level
        )
        attribs <- attribs[!sapply(attribs, is_empty)]

        if(is.numeric(regen_period))
            regen_period <- sprintf("P%sD", regen_period)

        body <- list(resourceId=storage_account, activeKeyName=key_name,
            autoRegenerateKey=regen_key, regenerationPeriod=regen_period,
            attributes=attribs, tags=list(...))

        self$do_operation(name, body=body, encode="json", http_verb="PUT")
        self$show(name)
    },

    show=function(name, version=NULL)
    {
        op <- construct_path(name, version)
        stored_account$new(self$token, self$url, name, version, self$do_operation(op))
    },

    remove=function(name, confirm=TRUE)
    {
        if(delete_confirmed(confirm, name, "storage account"))
            self$do_operation(name, http_verb="DELETE")
    },

    list_all=function()
    {
        lst <- lapply(get_vault_paged_list(self$do_operation(), self$token), function(props)
        {
            name <- basename(props$id)
            acct <- call_vault_url(self$token, props$id)
            stored_account$new(self$token, self$url, name, NULL, acct)
        })
        named_list(lst)
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

    do_operation=function(op="", ..., options=list(),
                          api_version=getOption("azure_keyvault_api_version"))
    {
        url <- self$url
        url$path <- construct_path("storage", op)
        url$query <- utils::modifyList(list(`api-version`=api_version), options)

        call_vault_url(self$token, url, ...)
    }
))
