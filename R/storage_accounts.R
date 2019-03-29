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

        body <- list(id=storage_account, activeKeyName=key_name,
            autoRegenerateKey=regen_key, regenerationPeriod=regen_period,
            attributes=attribs, tags=list(...))

        self$do_operation(name, body=body, encode="json", http_verb="PUT")
    },

    show=function(name, version=NULL)
    {
        op <- construct_path(name, version)
        self$do_operation(op)
    },

    remove=function(name, confirm=TRUE)
    {
        if(delete_confirmed(confirm, name, "key"))
            self$do_operation(name, http_verb="DELETE")
    },

    list_all=function()
    {
        lst <- get_vault_paged_list(self$do_operation(), self$token)
        names(lst) <- sapply(lst, function(x) basename(x$id))
        lst
    },

    versions_of=function(name)
    {
        op <- construct_path(name, "versions")
        lst <- get_vault_paged_list(self$do_operation(op), self$token)
        names(lst) <- sapply(lst, function(x) basename(x$id))
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

    do_operation=function(op="", ..., options=list(),
                          api_version=getOption("azure_keyvault_api_version"))
    {
        url <- self$url
        url$path <- construct_path("storage", op)
        url$query <- utils::modifyList(list(`api-version`=api_version), options)

        call_vault_url(self$token, url, ...)
    }
))
