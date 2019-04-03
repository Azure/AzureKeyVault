context("Resource creation")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
password <- Sys.getenv("AZ_TEST_PASSWORD")
vaultname <- Sys.getenv("AZ_TEST_KEYVAULT")

if(tenant == "" || app == "" || password == "" || vaultname == "")
    skip("Key tests skipped: vault credentials not set")

vault <- key_vault$new(vaultname, tenant=tenant, app=app, password=password)

try({
    vault$secrets$delete("secret1", confirm=FALSE)
}, silent=TRUE)


test_that("Secret interface works",
{
    secret1 <- vault$secrets$set("secret1", "mysecretvalue")
    expect_true(is.list(secret1) && secret1$value == "mysecretvalue")

    secret12 <- vault$secrets$set("secret1", "newsecretvalue", expiry_date="2099-01-01")
    expect_true(is.list(secret12) && secret12$value == "newsecretvalue")

    seclist <- vault$secrets$list_versions("secret1")
    expect_true(is.list(seclist) && length(seclist) == 2)

    lst <- vault$secrets$list_all()
    expect_true(is.list(lst) && length(lst) == 1)

    backup <- vault$secrets$backup("secret1")
    expect_type(backup, "character")
})

vault$secrets$delete("secret1", confirm=FALSE)

