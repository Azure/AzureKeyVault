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
                 attributes=vault_object_attrs(), ...)
    {
        if(is_resource(storage_account))
            storage_account <- storage_account$id

        if(is.numeric(regen_period))
            regen_period <- sprintf("P%sD", regen_period)

        # some attributes not used for storage accounts
        attributes$nbf <- attributes$exp <- NULL
        
        body <- list(resourceId=storage_account, activeKeyName=key_name,
            autoRegenerateKey=regen_key, regenerationPeriod=regen_period,
            attributes=attributes, tags=list(...))

        self$do_operation(name, body=body, encode="json", http_verb="PUT")
        self$get(name)
    },

    get=function(name, version=NULL)
    {
        op <- construct_path(name, version)
        stored_account$new(self$token, self$url, name, version, self$do_operation(op))
    },

    remove=function(name, confirm=TRUE)
    {
        if(delete_confirmed(confirm, name, "storage account"))
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

    do_operation=function(op="", ..., options=list(),
                          api_version=getOption("azure_keyvault_api_version"))
    {
        url <- self$url
        url$path <- construct_path("storage", op)
        url$query <- utils::modifyList(list(`api-version`=api_version), options)

        call_vault_url(self$token, url, ...)
    }
))
