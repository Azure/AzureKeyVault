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
    expect_true(inherits(rsacert, "stored_cert") && is.character(rsacert$cer))

    rsaval <- vault$certificates$get("rsacert")
    expect_true(inherits(rsaval, "stored_cert") && is.character(rsaval$cer))

    rsacert2 <- vault$certificates$create("rsacert", expiry_date="2099-01-01", issuer=list(name="self"),
        secret=list(contentType="application/x-pem-file"),
        x509=list(subject="CN=mydomain.com", sans=list(dns_names=list("mydomain.com"))))
    expect_true(inherits(rsacert2, "stored_cert") && is.character(rsacert2$cer))

    # need to wait for version listing to update, even though cert itself is complete
    Sys.sleep(30)

    rsalist <- vault$certificates$list_versions("rsacert")
    expect_true(is.list(rsalist) && length(rsalist) == 2 && all(sapply(rsalist, inherits, "stored_cert")))

    lst <- vault$certificates$list_all()
    expect_true(is.list(lst) && length(lst) == 1 && all(sapply(lst, inherits, "stored_cert")))

    backup <- vault$certificates$backup("rsacert")
    expect_type(backup, "character")
})

vault$certificates$delete("rsacert", confirm=FALSE)
