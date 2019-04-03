context("Certificate client interface")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
password <- Sys.getenv("AZ_TEST_PASSWORD")
vaultname <- Sys.getenv("AZ_TEST_KEYVAULT")

if(tenant == "" || app == "" || password == "" || vaultname == "")
    skip("Certificate tests skipped: vault credentials not set")

vault <- key_vault$new(vaultname, tenant=tenant, app=app, password=password)

try({
    vault$certificates$delete("rsacert", confirm=FALSE)
}, silent=TRUE)


test_that("Certficate interface works",
{
    rsacert <- vault$certificates$create("rsacert", issuer=list(name="self"),
        secret=list(contentType="application/x-pem-file"),
        x509=list(subject="CN=mydomain.com", sans=list(dns_names=list("mydomain.com"))))
    expect_true(is.list(rsacert) && is.character(rsacert$csr))

    # creating a cert has latency
    Sys.sleep(10)

    rsaval <- vault$certificates$show("rsacert")
    expect_true(is.list(rsaval) && is.character(rsaval$cer))

    rsacert2 <- vault$certificates$create("rsacert", expiry_date="2099-01-01", issuer=list(name="self"),
        secret=list(contentType="application/x-pem-file"),
        x509=list(subject="CN=mydomain.com", sans=list(dns_names=list("mydomain.com"))))
    expect_true(is.list(rsacert2) && is.character(rsacert2$csr))

    Sys.sleep(20)

    rsalist <- vault$certificates$list_versions("rsacert")
    expect_true(is.list(rsalist) && length(rsalist) == 2)

    lst <- vault$certificates$list_all()
    expect_true(is.list(lst) && length(lst) == 1)

    backup <- vault$certificates$backup("rsacert")
    expect_type(backup, "character")
})

vault$certificates$delete("rsacert", confirm=FALSE)
