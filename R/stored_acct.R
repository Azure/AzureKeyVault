#' Managed storage account
#'
#' This class represents a storage account that Key Vault will manage access to. It provides methods for regenerating keys, and managing shared access signatures (SAS).
#'
#' @docType class
#'
#' @section Fields:
#' This class provides the following fields:
#' - `id`: The internal vault ID of the storage account.
#' - `resourceId`: The Azure resource ID of the storage account.
#' - `activeKeyName`: The current active storage account key.
#' - `autoRegenerateKey`: Whether Key Vault will manage the storage account's key.
#' - `regenerationPeriod`: How often the account key is regenerated, in ISO 8601 format.
#'
#' @section Methods:
#' This class provides the following methods:
#' ```
#' regenerate_key(key_name)
#' create_sas_definition(sas_name, sas_template, validity_period, sas_type="account",
#'                       enabled=TRUE, recovery_level=NULL, ...)
#' delete_sas_definition(sas_name, confirm=TRUE)
#' get_sas_definition(sas_name)
#' list_sas_definitions()
#' show_sas(sas_name)
#'
#' update_attributes(attributes=vault_object_attrs(), ...)
#' remove(confirm=TRUE)
#' ```
#' @section Arguments:
#' - `key_name`: For `regenerate_key`, the name of the access key to regenerate.
#' - `sas_name`: The name of a SAS definition.
#' - `sas_template`: A string giving the details of the SAS to create. See 'Details' below.
#' - `validity_period`: How long the SAS should be valid for.
#' - `sas_type`: The type of SAS to generate, either "account" or "service".
#' - `enabled`: Whether the SAS definition. is enabled.
#' - `recovery_level`: The recovery level of the SAS definition.
#' - `...`: For `create_sas_definition`, other named arguments to use as tags for a SAS definition. For `update_attributes`, additional account-specific properties to update. See [storage_accounts].
#' - `attributes`: For `update_attributes`, the new attributes for the object, such as the expiry date and activation date. A convenient way to provide this is via the [vault_object_attrs] helper function.
#' - `confirm`: For `delete` and `delete_sas_definition`, whether to ask for confirmation before deleting.
#'
#' @section Details:
#' `create_sas_definition` creates a new SAS definition from a template. This can be created from the Azure Portal, via the Azure CLI, or in R via the AzureStor package (see examples). `get_sas_definition` returns a list representing the template definition; `show_sas` returns the actual SAS.
#'
#' `regenerate_key` manually regenerates an access key. Note that if the vault is setup to regenerate keys automatically, you won't usually have to use this method.
#'
#' Unlike the other objects stored in a key vault, storage accounts are not versioned.
#'
#' @section Value:
#' For `create_sas_definition` and `get_sas_definition`, a list representing the SAS definition. For `list_sas_definitions`, a list of such lists.
#'
#' For `show_sas`, a string containing the SAS.
#'
#' @seealso
#' [storage_accounts]
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
#' res <- AzureRMR::get_azure_login()$
#'     get_subscription("sub_id")$
#'     get_resource_group("rgname")$
#'     get_storage_account("mystorageacct")
#'
#' stor <- vault$storage$create("mystor", res, "key1")
#'
#' # Creating a new SAS definition
#' today <- Sys.time()
#' sasdef <- res$get_account_sas(expiry=today + 7*24*60*60, services="b", permissions="rw")
#' stor$create_sas_definition("newsas", sasdef, validity_period="P15D")
#'
#' stor$show_sas("newsas")
#'
#' }
#' @name storage_account
#' @rdname storage_account
NULL

stored_account <- R6::R6Class("stored_account", inherit=stored_object,

public=list(

    type="storage",

    id=NULL,
    resourceId=NULL,
    activeKeyName=NULL,
    autoRegenerateKey=NULL,
    regenerationPeriod=NULL,

    # change delete -> remove for storage accts
    delete=NULL,

    remove=function(confirm=TRUE)
    {
        if(delete_confirmed(confirm, self$name, "storage"))
            invisible(self$do_operation(version=NULL, http_verb="DELETE"))
    },

    regenerate_key=function(key_name)
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
            invisible(self$do_operation(op, http_verb="DELETE"))
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
    },

    print=function(...)
    {
        cat("<managed storage account '", self$name, "'>\n", sep="")
        cat("  account:", basename(self$resourceId), "\n")
        invisible(self)
    }
))
