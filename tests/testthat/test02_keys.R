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

    rsalist <- rsakey2$list_versions()
    expect_true(is.data.frame(rsalist) && nrow(rsalist) == 2)

    rsakey2$set_version(rsalist$version[2])
    expect_true(rsakey2$version == rsalist$version[2])

    eckey <- vault$keys$create("eckey", properties=key_properties(type="EC"))
    expect_true(inherits(eckey, "stored_key") && eckey$key$kty == "EC")

    extkey <- openssl::rsa_keygen()
    extkeyval <- jsonlite::fromJSON(jose::write_jwk(extkey))
    impkey <- vault$keys$import("extkey", key=extkey)
    expect_true(inherits(impkey, "stored_key") && impkey$key$kty == extkeyval$kty && impkey$key$n == extkeyval$n)

    lst <- vault$keys$list()
    expect_true(is.character(lst) && length(lst) == 3)

    backup <- vault$keys$backup("rsakey")
    expect_type(backup, "character")
})

vault$keys$delete("rsakey", confirm=FALSE)
vault$keys$delete("eckey", confirm=FALSE)
vault$keys$delete("extkey", confirm=FALSE)
