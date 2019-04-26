# AzureKeyVault

[Azure Key Vault](https://azure.microsoft.com/services/key-vault/) enables Microsoft Azure applications and users to store and use several types of secret/key data:

- Cryptographic keys: Supports multiple key types and algorithms, and enables the use of Hardware Security Modules (HSM) for high value keys.
- Secrets: Provides secure storage of secrets, such as passwords and database connection strings.
- Certificates: Supports certificates, which are built on top of keys and secrets and add an automated renewal feature.
- Azure Storage: Can manage keys of an Azure Storage account for you. Internally, Key Vault can list (sync) keys with an Azure Storage Account, and regenerate (rotate) the keys periodically.

AzureKeyVault is an R package for working with the Key Vault service. It provides both a client interface, to access the contents of the vault, and a Resource Manager interface for administering the Key Vault itself.

You can install the development version of the package from GitHub:

```r
devtools::install_github("cloudyr/AzureKeyVault")
```

## Resource Manager interface

AzureKeyVault extends the [AzureRMR](https://github.com/cloudyr/AzureRMR) package to handle key vaults. In addition to creating and deleting vaults, it provides methods to manage access policies for user and service principals.

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

The client interface is R6-based. To access the vault, instantiate a new object of class `key_vault`. This object includes sub-objects for interacting with keys, secrets, certificates and managed storage accounts.

```r
vault <- key_vault$new("https://mykeyvault.vault.azure.net")

# can also be done from the ARM resource object
vault <- kv$get_endpoint()


# create a new secret
vault$secrets$create("newsecret", "hidden text")
secret <- vault$secrets$get("newsecret")
secret$value
#> [1] "hidden text"


# create a new RSA key with 4096-bit key size
vault$keys$create("newkey", properties=key_properties(type="RSA", rsa_key_size=4096))

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

# export the certificate as a PEM file
cert$export("newcert.pem")

# import a certificate from a PFX file
vault$certificates$import("importedcert", "mycert.pfx")

## signing a JSON web token (JWT) for authenticating with Azure Active Directory
app <- "app_id"
tenant <- "tenant_id"
claim <- jose::jwt_claim(
    iss=app,
    sub=app,
    aud="https://login.microsoftonline.com/tenant_id/oauth2/token",
    exp=as.numeric(Sys.time() + 60*60),
    nbf=as.numeric(Sys.time())
)
# header includes cert thumbprint
header <- list(alg="RS256", typ="JWT", x5t=cert$x5t)

token_encode <- function(x)
{
    jose::base64url_encode(jsonlite::toJSON(x, auto_unbox=TRUE))
}
token_contents <- paste(token_encode(header), token_encode(claim), sep=".")

# get the signature and concatenate it with header and claim to form JWT
sig <- cert$sign(openssl::sha256(charToRaw(token_contents)))
cert_creds <- paste(token_contents, sig, sep=".")

AzureAuth::get_azure_token("resource_url", tenant, app, certificate=cert_creds)


# add a managed storage account
stor <- rg$get_resource(type="Microsoft.Storage/storageAccounts", name="mystorage")
vault$storage$add("mystorage", stor, "key1")
```

---
[![cloudyr project logo](https://i.imgur.com/JHS98Y7.png)](https://github.com/cloudyr)
