context("Key client interface")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
password <- Sys.getenv("AZ_TEST_PASSWORD")
vaultname <- Sys.getenv("AZ_TEST_KEYVAULT")

if(tenant == "" || app == "" || password == "" || vaultname == "")
    skip("Key tests skipped: vault credentials not set")

vault <- key_vault$new(vaultname, tenant=tenant, app=app, password=password)

try({
    vault$keys$delete("rsakey", confirm=FALSE)
    vault$keys$delete("eckey", confirm=FALSE)
    vault$keys$delete("extkey", confirm=FALSE)
}, silent=TRUE)


test_that("Key interface works",
{
    rsakey <- vault$keys$create("rsakey")
    expect_true(inherits(rsakey, "stored_key"))

    rsaval <- vault$keys$get("rsakey")
    expect_true(inherits(rsaval, "stored_key") && is.character(rsaval$key$n))

    rsakey2 <- vault$keys$create("rsakey", expiry_date="2099-01-01")
    expect_true(inherits(rsakey2, "stored_key") && rsakey2$key$kty == "RSA")

    rsalist <- vault$keys$list_versions("rsakey")
    expect_true(is.list(rsalist) && length(rsalist) == 2 && all(sapply(rsalist, inherits, "stored_key")))

    eckey <- vault$keys$create("eckey", type="EC")
    expect_true(inherits(eckey, "stored_key") && eckey$key$kty == "EC")

    extkey <- openssl::rsa_keygen()
    extkeyval <- jsonlite::fromJSON(jose::write_jwk(extkey))
    impkey <- vault$keys$import("extkey", key=extkey)
    expect_true(inherits(impkey, "stored_key") && impkey$key$kty == extkeyval$kty && impkey$key$n == extkeyval$n)

    lst <- vault$keys$list_all()
    expect_true(is.list(lst) && length(lst) == 3 && all(sapply(lst, inherits, "stored_key")))

    backup <- vault$keys$backup("rsakey")
    expect_type(backup, "character")
})

vault$keys$delete("rsakey", confirm=FALSE)
vault$keys$delete("eckey", confirm=FALSE)
vault$keys$delete("extkey", confirm=FALSE)
