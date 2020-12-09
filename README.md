# AzureKeyVault <img src="man/figures/logo.png" align="right" width=150 />

[![CRAN](https://www.r-pkg.org/badges/version/AzureKeyVault)](https://cran.r-project.org/package=AzureKeyVault)
![Downloads](https://cranlogs.r-pkg.org/badges/AzureKeyVault)
![R-CMD-check](https://github.com/AzureRSDK/AzureKeyVault/workflows/R-CMD-check/badge.svg)

[Azure Key Vault](https://azure.microsoft.com/services/key-vault/) enables Microsoft Azure applications and users to store and use several types of secret/key data:

- Cryptographic keys: Supports multiple key types and algorithms, and enables the use of Hardware Security Modules (HSM) for high value keys.
- Secrets: Provides secure storage of secrets, such as passwords and database connection strings.
- Certificates: Supports certificates, which are built on top of keys and secrets and add an automated renewal feature.
- Azure Storage: Can manage keys of an Azure Storage account for you. Internally, Key Vault can list (sync) keys with an Azure Storage Account, and regenerate (rotate) the keys periodically.

AzureKeyVault is an R package for working with the Key Vault service. It provides both a client interface, to access the contents of the vault, and a Resource Manager interface for administering the Key Vault itself.

The primary repo for this package is at https://github.com/AzureRSDK/AzureKeyVault; please submit issues and PRs there. It is also mirrored at the Cloudyr org at https://github.com/cloudyr/AzureKeyVault. You can install the development version of the package from GitHub:

```r
devtools::install_github("AzureRSDK/AzureKeyVault")
```

## Resource Manager interface

AzureKeyVault extends the [AzureRMR](https://github.com/AzureRSDK/AzureRMR) package to handle key vaults. In addition to creating and deleting vaults, it provides methods to manage access policies for user and service principals.

```r
# create a key vault
rg <- AzureRMR::get_azure_login()$
    get_subscription("sub_id")$
    get_resource_group("rgname")
kv <- rg$create_key_vault("mykeyvault")

# list current principals (by default includes logged-in user)
kv$list_principals()

# get details for a service principal
svc <- AzureGraph::get_graph_login()$
    get_service_principal("app_id")

# give the service principal read-only access to vault keys and secrets
kv$add_principal(svc,
    key_permissions=c("get", "list", "backup"),
    secret_permissions=c("get", "list", "backup"),
    certificate_permissions=NULL,
    storage_permissions=NULL)
```

## Client interface

The client interface is R6-based. To instantiate a new client object, call the `key_vault` function. This object includes sub-objects for interacting with keys, secrets, certificates and managed storage accounts.

```r
vault <- key_vault("https://mykeyvault.vault.azure.net")

# can also be done from the ARM resource object
vault <- kv$get_endpoint()


# create a new secret
vault$secrets$create("newsecret", "hidden text")
secret <- vault$secrets$get("newsecret")

# printing the value won't display it; this is to help guard against shoulder-surfing
secret$value
#> <hidden>


# create a new RSA key with 4096-bit key size
vault$keys$create("newkey", type="RSA", rsa_key_size=4096)

# encrypting and decrypting
key <- vault$keys$get("newkey")
plaintext <- "super secret"
ciphertext <- key$encrypt(plaintext)
decrypted_text <- key$decrypt(ciphertext, as_raw=FALSE)
plaintext == decrypted_text
#> [1] TRUE


# create a new self-signed certificate (will also create an associated key and secret)
cert <- vault$certificates$create("newcert",
    subject="CN=mydomain.com",
    x509=cert_x509_properties(dns_names="mydomain.com"))

# import a certificate from a PFX file
vault$certificates$import("importedcert", "mycert.pfx")

# OAuth authentication using a cert in Key Vault (requires AzureAuth >= 1.0.2)
AzureAuth::get_azure_token("resource_url", "mytenant", "app_id", certificate=cert)

# export the certificate as a PEM file
# (you should only export a cert if absolutely necessary)
cert$export("newcert.pem")


# add a managed storage account
storage_res <- rg$get_resource(type="Microsoft.Storage/storageAccounts", name="mystorage")
stor <- vault$storage$add("mystorage", storage_res, "key1")

# Creating a new SAS definition
sasdef <- "sv=2015-04-05&ss=bqtf&srt=sco&sp=r"
stor$create_sas_definition("newsas", sasdef, validity_period="P30D")
```

---
<p align="center"><a href="https://github.com/AzureRSDK/AzureR"><img src="https://github.com/AzureRSDK/AzureR/raw/master/images/logo2.png" width=800 /></a></p>
