context("Character string token")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
password <- Sys.getenv("AZ_TEST_PASSWORD")
vaultname <- Sys.getenv("AZ_TEST_KEYVAULT")

if(tenant == "" || app == "" || password == "" || vaultname == "")
    skip("Key tests skipped: vault credentials not set")

vault0 <- key_vault(vaultname, tenant=tenant, app=app, password=password)

try({
    vault0$keys$delete("chartokkey", confirm=FALSE)
    vault0$secrets$delete("chartoksecret", confirm=FALSE)
    vault0$certificates$delete("chartokcert", confirm=FALSE)
}, silent=TRUE)


test_that("Token as character string works",
{
    token <- vault0$token$credentials$access_token
    expect_is(token, "character")

    vault <- key_vault(vaultname, token=token)
    expect_is(vault, "AzureKeyVault")

    key <- vault$keys$create("chartokkey")
    expect_true(inherits(key, "stored_key"))

    secret <- vault$secrets$create("chartoksecret", "mysecretvalue")
    expect_true(inherits(secret, "stored_secret"))

    cert <- vault$certificates$create("chartokcert",
        subject="CN=example.com",
        x509=cert_x509_properties(dns_names="example.com"))
    expect_true(inherits(cert, "stored_cert") && is.character(cert$cer))
})


vault0$keys$delete("chartokkey", confirm=FALSE)
vault0$secrets$delete("chartoksecret", confirm=FALSE)
vault0$certificates$delete("chartokcert", confirm=FALSE)
