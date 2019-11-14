context("Soft delete and purge")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
password <- Sys.getenv("AZ_TEST_PASSWORD")
subscription <- Sys.getenv("AZ_TEST_SUBSCRIPTION")
username <- Sys.getenv("AZ_TEST_USERNAME")

if(tenant == "" || app == "" || password == "" || subscription == "" || username == "")
    skip("Tests skipped: ARM credentials not set")

rgname <- paste(sample(letters, 20, replace=TRUE), collapse="")
rg2name <- paste(sample(letters, 20, replace=TRUE), collapse="")
kvsoftname <- paste(sample(letters, 10, replace=TRUE), collapse="")
kvhardname <- paste(sample(letters, 10, replace=TRUE), collapse="")

sub <- AzureRMR::az_rm$
    new(tenant=tenant, app=app, password=password)$
    get_subscription(subscription)

rg <- sub$create_resource_group(rgname, location="australiaeast")
rg2 <- sub$create_resource_group(rg2name, location="australiaeast")


test_that("Resource soft delete works",
{
    kvsoft <- rg$create_key_vault(kvsoftname, soft_delete=TRUE)
    kvsoft_vault <- kvsoft$get_endpoint()
    kvsoft_vault$secrets$create("mysecret", "value")

    expect_message(kvsoft$delete(confirm=FALSE))
    Sys.sleep(30)

    # recreating a soft-deleted vault in another RG should fail
    expect_error(rg2$create_key_vault(kvsoftname))

    # but recreating it in the same RG should work
    expect_message(rg$create_key_vault(kvsoftname, soft_delete=TRUE))

    # contents should survive soft delete
    kvsoft_vault <- rg$get_key_vault(kvsoftname)$get_endpoint()
    expect_is(kvsoft_vault$secrets$get("mysecret"), "stored_secret")

    expect_message(kvsoft$delete(confirm=FALSE, purge=TRUE))
    Sys.sleep(30)

    deleted <- sub$list_deleted_key_vaults()
    expect_false(kvsoftname %in% deleted$name)

    # after purge, recreating in another RG should work
    expect_is(rg2$create_key_vault(kvsoftname), "az_key_vault")
    expect_true(is_empty(rg2$get_key_vault(kvsoftname)$get_endpoint()$secrets$list()))

    expect_message(rg2$delete_key_vault(kvsoftname, confirm=FALSE, purge=TRUE))
})


test_that("Resource hard delete works",
{
    kvhard <- rg$create_key_vault(kvhardname, soft_delete=FALSE)
    kvhard_vault <- kvhard$get_endpoint()
    kvhard_vault$secrets$create("mysecret", "value")

    expect_message(kvhard$delete(confirm=FALSE))
    Sys.sleep(30)

    # recreating a hard-deleted vault should always work
    expect_is(rg2$create_key_vault(kvhardname, soft_delete=FALSE), "az_key_vault")
    expect_true(is_empty(rg2$get_key_vault(kvhardname)$get_endpoint()$secrets$list()))

    # purge should be a no-op with hard delete
    expect_message(rg2$delete_key_vault(kvhardname, confirm=FALSE, purge=TRUE))
})
