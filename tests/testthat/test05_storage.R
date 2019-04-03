context("Storage account client interface")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
password <- Sys.getenv("AZ_TEST_PASSWORD")
vaultname <- Sys.getenv("AZ_TEST_KEYVAULT")
subscription <- Sys.getenv("AZ_TEST_SUBSCRIPTION")
rgname <- Sys.getenv("AZ_TEST_KEYVAULT_RGNAME")
storname <- Sys.getenv("AZ_TEST_KEYVAULT_STORAGE")

if(tenant == "" || app == "" || password == "" || vaultname == "" ||
   subscription == "" || rgname == "" || storname == "")
    skip("Storage account tests skipped: vault credentials not set")

# currently storage acct management requires a user principal, not svc principal
#vault <- key_vault$new(vaultname, tenant=tenant, app=app, password=password)
vault <- key_vault$new(vaultname)

try({
    vault$storage$remove("stor1", confirm=FALSE)
}, silent=TRUE)


test_that("Storage account interface works",
{
    stor <- az_rm$new(tenant, app, password)$
        get_subscription(subscription)$
        get_resource_group(rgname)$
        get_resource(type="Microsoft.Storage/storageAccounts", name=storname)

    stor1 <- vault$storage$add("stor1", stor, "key1", regen_period="P30D")
    expect_true(is.list(stor1) && stor1$resourceId == stor$id)

    lst <- vault$storage$list_all()
    expect_true(is.list(lst) && length(lst) == 1)

    backup <- vault$storage$backup("stor1")
    expect_type(backup, "character")
})

vault$storage$remove("stor1", confirm=FALSE)

