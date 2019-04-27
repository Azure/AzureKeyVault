#' Storage accounts in Key Vault
#'
#' This class represents the collection of storage accounts managed by a vault. It provides methods for adding and removing accounts, and doing backups and restores. For operations with a specific account, see [storage].
#'
#' @docType class
#'
#' @section Methods:
#' This class provides the following methods:
#' ```
#' add(name, storage_account, key_name, regen_key=TRUE, regen_period=30,
#'     attributes=vault_object_attrs(), ...)
#' get(name)
#' remove(name, confirm=TRUE)
#' list()
#' backup(name)
#' restore(backup)
#' ```
#' @section Arguments:
#' - `name`: A name by which to refer to the storage account.
#' - `storage_account`: The Azure resource ID of the account. This can also be an object of class `az_resource` or `az_storage`, as provided by the AzureRMR or AzureStor packages respectively; in this case, the resource ID is obtained from the object.
#' - `key_name`: The name of the storage access key that Key Vault will manage.
#' - `regen_key`: Whether to automatically regenerate the access key at periodic intervals.
#' - `regen_period`: How often to regenerate the access key. This can be a number, which will be interpreted as days; or as an ISO-8601 string denoting a duration, eg "P30D" (30 days).
#' - `attributes`: Optional attributes for the secret. A convenient way to provide this is via the [vault_object_attrs] helper function.
#' - `...`: For `create` and `import`, other named arguments which will be treated as tags.
#' - `confirm`: For `remove`, whether to ask for confirmation before removing the account.
#' - `backup`: For `restore`, a string representing the backup blob for a key.
#' - `email`: For `set_contacts`, the email addresses of the contacts.
#'
#' @section Value:
#' For `get` and `add`, an object of class `stored_account`, representing the storage account itself.
#'
#' For `list`, a vector of account names.
#'
#' For `backup`, a string representing the backup blob for a storage account. If the account has multiple versions, the blob will contain all versions.
#'
#' @seealso
#' [storage_account], [vault_object_attrs]
#'
#' [Azure Key Vault documentation](https://docs.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://docs.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' vault <- key_vault("mykeyvault")
#'
#' # get the storage account details
#' library(AzureStor)
#' stor <- AzureRMR::get_azure_login()$
#'     get_subscription("sub_id")$
#'     get_resource_group("rgname")$
#'     get_storage_account("mystorageacct")
#' vault$storage$create("mystor", stor, "key1")
#'
#' vault$storage$list()
#' vault$storage$get("mystor")
#'
#' # specifying a regeneration period of 6 months
#' vault$storage$create("mystor", regen_period="P6M")
#'
#' # setting management tags
#' vault$storage$create("mystor", tag1="a value", othertag="another value")
#'
#' # backup and restore an account
#' bak <- vault$storage$backup("mystor")
#' vault$storage$delete("mystor", confirm=FALSE)
#' vault$storage$restore(bak)
#' 
#' }
#' @name storage_accounts
#' @aliases storage_accounts storage
#' @rdname storage_accounts
NULL

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
            invisible(self$do_operation(name, http_verb="DELETE"))
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
    },

    print=function(...)
    {
        url <- self$url
        url$path <- "storage"
        cat("<key vault endpoint '", httr::build_url(url), "'>\n", sep="")
        invisible(self)
    }
))
