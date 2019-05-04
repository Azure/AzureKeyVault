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
#vault <- key_vault(vaultname, tenant=tenant, app=app, password=password)
vault <- key_vault(vaultname)

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
    expect_true(inherits(stor1, "stored_account") && stor1$resourceId == stor$id)

    lst <- vault$storage$list()
    expect_true(is.character(lst) && length(lst) == 1)

    backup <- vault$storage$backup("stor1")
    expect_type(backup, "character")

    # SAS template (unsigned)
    sas <- "sv=2015-04-05&ss=bqtf&srt=sco&sp=r"

    sasdef <- stor1$create_sas_definition("testsas", sas_template=sas, validity_period="P15D")
    expect_true(is.list(sasdef) && is.character(sasdef$sid))

    sasdef2 <- stor1$get_sas_definition("testsas")
    expect_true(is.list(sasdef2) && !is.null(sasdef2$sid))

    sasnew <- stor1$show_sas("testsas")
    expect_true(is.character(sasnew) && substr(sasnew, 1, 1) == "?")

    expect_silent(stor1$delete_sas_definition("testsas", confirm=FALSE))
})

vault$storage$remove("stor1", confirm=FALSE)

