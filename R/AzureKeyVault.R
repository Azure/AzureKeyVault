#' @import AzureRMR
#' @import AzureGraph
NULL

utils::globalVariables(c("self", "private"))

.az_cli_app_id <- "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

.onLoad <- function(libname, pkgname)
{
    options(azure_keyvault_api_version="7.0")
    add_methods()
}
