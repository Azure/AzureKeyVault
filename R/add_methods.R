add_methods <- function()
{
    ## extending AzureRMR classes

    AzureRMR::az_resource_group$set("public", "create_vault", overwrite=TRUE,
    function(name, location=self$location, access=configure_vault_access(), sku="Standard", ...)
    {
        configure_vault_access=function()
        {
            creds <- decode_jwt(self$token$credentials$access_token)
            tenant <- creds$tid
            owner <- creds$oid
        }

        props <- utils::modifyList(
            list(accessPolicies=access, sku=list(family="A", name=sku)),
            list(...)
        )

        AzureKeyVault::az_vault$new(self$token, self$subscription, self$name,
            type="Microsoft.KeyVault/vaults", name=name, location=location,
            properties=props, wait=wait)
    })


    AzureRMR::az_resource_group$set("public", "get_vault", overwrite=TRUE,
    function(name)
    {
        AzureKeyVault::az_vault$new(self$token, self$subscription, self$name,
            type="Microsoft.KeyVault/vaults", name=name)
    })


    AzureRMR::az_resource_group$set("public", "delete_vault", overwrite=TRUE,
    function(name, confirm=TRUE, wait=FALSE)
    {
        self$get_vault(name)$delete(confirm=confirm, wait=wait)
    })
}
