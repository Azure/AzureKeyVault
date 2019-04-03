add_methods <- function()
{
    ## extending AzureRMR classes

    AzureRMR::az_resource_group$set("public", "create_key_vault", overwrite=TRUE,
    function(name, location=self$location, initial_access=default_access(), sku="Standard", ..., wait=TRUE)
    {
        creds <- decode_jwt(self$token$credentials$access_token)
        tenant <- creds$payload$tid

        default_access=function()
        {
            principal <- creds$payload$oid
            list(vault_access_policy(principal, tenant, "all", "all", "all", "all"))
        }

        props <- utils::modifyList(
            list(
                tenantId=tenant,
                accessPolicies=lapply(initial_access, function(x)
                {
                    if(is.null(x$tenantId))
                        x$tenantId <- tenant
                    unclass(x)
                }),
                sku=list(family="A", name=sku)
            ),
            list(...)
        )

        AzureKeyVault::az_key_vault$new(self$token, self$subscription, self$name,
            type="Microsoft.KeyVault/vaults", name=name, location=location,
            properties=props, wait=wait)
    })


    AzureRMR::az_resource_group$set("public", "get_key_vault", overwrite=TRUE,
    function(name)
    {
        AzureKeyVault::az_key_vault$new(self$token, self$subscription, self$name,
            type="Microsoft.KeyVault/vaults", name=name)
    })


    AzureRMR::az_resource_group$set("public", "delete_key_vault", overwrite=TRUE,
    function(name, confirm=TRUE, wait=FALSE)
    {
        self$get_key_vault(name)$delete(confirm=confirm, wait=wait)
    })
}
