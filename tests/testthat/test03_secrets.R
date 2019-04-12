context("Secret client interface")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
password <- Sys.getenv("AZ_TEST_PASSWORD")
vaultname <- Sys.getenv("AZ_TEST_KEYVAULT")

if(tenant == "" || app == "" || password == "" || vaultname == "")
    skip("Secret tests skipped: vault credentials not set")

vault <- key_vault$new(vaultname, tenant=tenant, app=app, password=password)

try({
    vault$secrets$delete("secret1", confirm=FALSE)
}, silent=TRUE)


test_that("Secret interface works",
{
    secret1 <- vault$secrets$create("secret1", "mysecretvalue")
    expect_true(inherits(secret1, "stored_secret") && secret1$value == "mysecretvalue")

    secret12 <- vault$secrets$create("secret1", "newsecretvalue", expiry_date="2099-01-01")
    expect_true(inherits(secret12, "stored_secret") && secret12$value == "newsecretvalue")

    seclist <- secret12$list_versions()
    expect_true(is.data.frame(seclist) && nrow(seclist) == 2)

    secret12$set_version(seclist$version[2])
    expect_true(secret12$version == seclist$version[2])

    lst <- vault$secrets$list_all()
    expect_true(is.list(lst) && length(lst) == 1 && all(sapply(lst, inherits, "stored_secret")))

    backup <- vault$secrets$backup("secret1")
    expect_type(backup, "character")
})

vault$secrets$delete("secret1", confirm=FALSE)

