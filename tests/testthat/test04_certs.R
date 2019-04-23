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
    vault$certificates$delete("pfxcert", confirm=FALSE)
}, silent=TRUE)


test_that("Certficate interface works",
{
    rsacert <- vault$certificates$create("rsacert",
        subject="CN=example.com",
        x509=cert_x509_properties(dns_names="example.com"))
    expect_true(inherits(rsacert, "stored_cert") && is.character(rsacert$cer))

    rsaval <- vault$certificates$get("rsacert")
    expect_true(inherits(rsaval, "stored_cert") && is.character(rsaval$cer))

    rsacert2 <- vault$certificates$create("rsacert",
        subject="CN=example.com",
        x509=cert_x509_properties(dns_names="example.com"),
        attributes=vault_object_attrs(expiry_date="2099-01-01"))
    expect_true(inherits(rsacert2, "stored_cert") && is.character(rsacert2$cer))

    pemfile <- tempfile(fileext=".pem")
    expect_silent(rsacert$export(pemfile))
    expect_true(file.exists(pemfile) && file.info(pemfile)$size > 0)

    pfxcert <- vault$certificates$create("pfxcert",
        subject="CN=example.com",
        format="pfx")
    expect_true(inherits(pfxcert, "stored_cert") && is.character(pfxcert$cer))

    pfxfile <- tempfile(fileext=".pfx")
    expect_silent(pfxcert$export(pfxfile))
    expect_true(file.exists(pfxfile) && file.info(pfxfile)$size > 0)

    # need to wait for version listing to update, even though cert itself is complete
    Sys.sleep(30)

    rsalist <- rsacert$list_versions()
    expect_true(is.data.frame(rsalist) && nrow(rsalist) == 2)

    lst <- vault$certificates$list()
    expect_true(is.character(lst) && length(lst) == 2)

    backup <- vault$certificates$backup("rsacert")
    expect_type(backup, "character")
})

vault$certificates$delete("rsacert", confirm=FALSE)
vault$certificates$delete("pfxcert", confirm=FALSE)
