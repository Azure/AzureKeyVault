context("Certificate client interface")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
password <- Sys.getenv("AZ_TEST_PASSWORD")
vaultname <- Sys.getenv("AZ_TEST_KEYVAULT")

if(tenant == "" || app == "" || password == "" || vaultname == "")
    skip("Certificate tests skipped: vault credentials not set")

vault <- key_vault(vaultname, tenant=tenant, app=app, password=password)

try({
    vault$certificates$delete("rsacert", confirm=FALSE)
    vault$certificates$delete("pfxcert", confirm=FALSE)
    vault$certificates$delete("notifycert", confirm=FALSE)
    vault$certificates$set_contacts(NULL)
    vault$certificates$remove_issuer("issuer1")
}, silent=TRUE)


test_that("Certificate interface works",
{
    rsacert <- vault$certificates$create("rsacert",
        subject="CN=example.com",
        x509=cert_x509_properties(dns_names="example.com"))
    expect_true(inherits(rsacert, "stored_cert") && is.character(rsacert$cer))

    rsaval <- vault$certificates$get("rsacert")
    expect_true(inherits(rsaval, "stored_cert") && is.character(rsaval$cer))

    rsacert2 <- vault$certificates$create("rsacert",
        subject="CN=example.com",
        x509=cert_x509_properties(dns_names="example.com", validity_months=24),
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

    notifycert <- vault$certificates$create("notifycert",
        subject="CN=example.com",
        expiry_action=cert_expiry_action(action="EmailContacts"))
    expect_true(inherits(notifycert, "stored_cert") && is.character(notifycert$cer) &&
        notifycert$policy$lifetime_actions[[1]]$action$action_type == "EmailContacts")

    # need to wait for version listing to update, even though cert itself is complete
    Sys.sleep(30)

    rsalist <- rsacert$list_versions()
    expect_true(is.data.frame(rsalist) && nrow(rsalist) == 2)

    lst <- vault$certificates$list()
    expect_true(is.character(lst) && length(lst) == 3)

    backup <- vault$certificates$backup("rsacert")
    expect_type(backup, "character")

    expect_silent(vault$certificates$set_contacts("name@example.com"))
    expect_type(vault$certificates$get_contacts(), "list")
    expect_silent(vault$certificates$set_contacts(NULL))

    expect_silent(vault$certificates$add_issuer("issuer1", provider="OneCert"))
    expect_type(vault$certificates$list_issuers(), "character")
    expect_silent(vault$certificates$remove_issuer("issuer1"))
})

vault$certificates$delete("rsacert", confirm=FALSE)
vault$certificates$delete("pfxcert", confirm=FALSE)
vault$certificates$delete("notifycert", confirm=FALSE)
