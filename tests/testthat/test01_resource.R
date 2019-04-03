context("Resource creation")

tenant <- Sys.getenv("AZ_TEST_TENANT_ID")
app <- Sys.getenv("AZ_TEST_APP_ID")
password <- Sys.getenv("AZ_TEST_PASSWORD")
subscription <- Sys.getenv("AZ_TEST_SUBSCRIPTION")
username <- Sys.getenv("AZ_TEST_USERNAME")

if(tenant == "" || app == "" || password == "" || subscription == "" || username == "")
    skip("Tests skipped: ARM credentials not set")

if(!requireNamespace("AzureGraph", quietly=TRUE))
    skip("Resource creation tests skipped, AzureGraph not installed")

rgname <- paste(sample(letters, 20, replace=TRUE), collapse="")
kvname <- paste(sample(letters, 10, replace=TRUE), collapse="")

rg <- AzureRMR::az_rm$
    new(tenant=tenant, app=app, password=password)$
    get_subscription(subscription)$
    create_resource_group(rgname, location="australiaeast")


test_that("Access policy function works",
{
    pol0 <- vault_access_policy(app, NULL, NULL, NULL, NULL, NULL)
    expect_is(pol0, "vault_access_policy")
    expect_true(AzureRMR::is_empty(pol0$key_permissions))
    expect_true(AzureRMR::is_empty(pol0$secret_permissions))
    expect_true(AzureRMR::is_empty(pol0$certificate_permissions))
    expect_true(AzureRMR::is_empty(pol0$storage_permissions))

    usr <- AzureGraph::ms_graph$
        new(tenant=tenant)$
        get_user(username)

    pol1 <- vault_access_policy(usr, NULL)
    expect_identical(pol1$objectId, usr$properties$id)
    expect_identical(pol1$permissions$keys,
        I(c("get", "list", "update", "create", "import", "delete", "recover", "backup", "restore",
            "decrypt", "encrypt", "unwrapkey", "wrapkey", "verify", "sign", "purge")))
    expect_identical(pol1$permissions$secrets,
        I(c("get", "list", "set", "delete", "recover", "backup", "restore", "purge")))
    expect_identical(pol1$permissions$certificates,
        I(c("get", "list", "update", "create", "import", "delete", "recover", "backup", "restore",
            "managecontacts", "manageissuers", "getissuers", "listissuers", "setissuers",
            "deleteissuers", "purge")))
    expect_identical(pol1$permissions$storage,
        I(c("backup", "delete", "deletesas", "get", "getsas", "list", "listsas",
            "purge", "recover", "regeneratekey", "restore", "set", "setsas", "update")))

    expect_error(vault_access_policy(username)) # must supply GUID or Graph object as principal
    expect_error(vault_access_policy(usr, NULL, key_permissions="none"))
    expect_error(vault_access_policy(usr, NULL, secret_permissions="none"))
    expect_error(vault_access_policy(usr, NULL, certificate_permissions="none"))
    expect_error(vault_access_policy(usr, NULL, storage_permissions="none"))

    pol2 <- vault_access_policy(usr, NULL, "get", "get", "get", "get")
    expect_is(pol2, "vault_access_policy")
    expect_identical(pol2$permissions$keys, I("get"))
    expect_identical(pol2$permissions$secrets, I("get"))
    expect_identical(pol2$permissions$certificates, I("get"))
    expect_identical(pol2$permissions$storage, I("get"))
})

test_that("Resource creation works",
{
    kv <- rg$create_key_vault(kvname)
    expect_is(kv, "az_key_vault")

    kv2 <- rg$get_key_vault(kvname)
    expect_is(kv2, "az_key_vault")
})

test_that("Access policy management works",
{
    kv <- rg$get_key_vault(kvname)

    usr <- AzureGraph::ms_graph$
        new(tenant=tenant)$
        get_user(username)

    kv$add_principal(usr)
    pols <- kv$properties$accessPolicies
    expect_true(any(sapply(pols, function(x) x$objectId == usr$properties$id)))

    kv$remove_principal(usr)
    pols <- kv$properties$accessPolicies
    expect_false(any(sapply(pols, function(x) x$objectId == usr$properties$id)))
})

test_that("Resource deletion works",
{
    expect_message(rg$delete_key_vault(kvname, confirm=FALSE))
})


rg$delete(confirm=FALSE)
