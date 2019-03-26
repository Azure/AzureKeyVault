#' @import AzureRMR
NULL

utils::globalVariables("self")

.onLoad <- function(libname, pkgname)
{
    options(azure_keyvault_api_version="7.0")
    make_AzureR_dir()
}
