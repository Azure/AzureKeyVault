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

    # SAS template (unsigned)
    sas <- "sv=2015-04-05&ss=bqtf&srt=sco&sp=r&st=2019-01-01T00%3A00%3A00.0000000Z&se=2099-01-01T00%3A00%3A00.0000000Z"

    sasdef <- vault$storage$create_sas_definition("stor1", "testsas", sas_template=sas, validity_period="P15D")
    expect_true(is.list(sasdef) && is.character(sasdef$sid))

    sasdef2 <- vault$storage$get_sas_definition("stor1", "testsas")
    expect_true(is.list(sasdef2) && !is.null(sasdef2$sid))

    sasnew <- vault$storage$show_sas("stor1", "testsas")
    expect_true(is.character(sasnew) && substr(sasnew, 1, 1) == "?")

    expect_silent(vault$storage$delete_sas_definition("stor1", "testsas", confirm=FALSE))
})

vault$storage$remove("stor1", confirm=FALSE)

