#' Certificate object
#'
#' This class represents a certificate stored in a vault. It provides methods for carrying out operations, including encryption and decryption, signing and verification, and wrapping and unwrapping.
#'
#' @docType class
#'
#' @section Fields:
#' This class provides the following fields:
#' - `cer`: The contents of the certificate, in CER format.
#' - `id`: The ID of the certificate.
#' - `kid`: The ID of the key backing the certificate.
#' - `sid`: The ID of the secret backing the certificate.
#' - `contentType`: The content type of the secret backing the certificate.
#' - `policy`: The certificate management policy, containing the authentication details.
#' - `x5t`: The thumbprint of the certificate.
#'
#' @section Methods:
#' This class provides the following methods:
#' ```
#' export(file)
#' set_policy(subject=NULL, x509=NULL, issuer=NULL,
#'            key=NULL, secret_type=NULL, actions=NULL,
#'            attributes=NULL, wait=TRUE)
#' get_policy()
#' sync()
#'
#' update_attributes(attributes=vault_object_attrs(), ...)
#' list_versions()
#' set_version(version=NULL)
#' delete(confirm=TRUE)
#' ```
#' @section Arguments:
#' - `file`: For `export`, a connection object or a character string naming a file to export to.
#' - `subject,x509,issuer,key,secret_type,actions,wait`: These are the same arguments as used when creating a new certificate. See [certificates] for more information.
#' - `attributes`: For `update_attributes`, the new attributes for the object, such as the expiry date and activation date. A convenient way to provide this is via the [vault_object_attrs] helper function.
#' - `...`: For `update_attributes`, additional key-specific properties to update. See [keys].
#' - `version`: For `set_version`, the version ID or NULL for the current version.
#' - `confirm`: For `delete`, whether to ask for confirmation before deleting the key.
#'
#' @section Details:
#' `export` exports the certificate to a file. The format wll be either PEM or PFX (aka PKCS#12), as set by the `format` argument when the certificate was created.
#'
#' `set_policy` updates the authentication details of a certificate: its issuer, identity, key type, renewal actions, and so on. `get_policy` returns the current policy of a certificate.
#'
#' A certificate can have multiple _versions_, which are automatically generated when a cert is created with the same name as an existing cert. By default, this object contains the information for the most recent (current) version; use `list_versions` and `set_version` to change the version.
#'
#' @section Value:
#' For `get_policy`, a list of certificate policy details.
#'
#' For `list_versions`, a vector of certificate version IDs.
#'
#' For `set_version`, the key object with the updated version.
#'
#' @seealso
#' [certificates]
#'
#' [Azure Key Vault documentation](https://docs.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://docs.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' vault <- key_vault$new("mykeyvault")
#'
#' cert <- vault$certificates$create("mynewcert")
#' cert$cer
#'
#' # new version of an existing certificate
#' vault$certificates$create("mynewcert", x509=cert_x509_properties(valid=24))
#'
#' cert <- vault$certificates$get("mynewcert")
#' vers <- cert$list_versions()
#' cert$set_version(vers[2])
#'
#' # updating an existing cert version
#' cert$set_policy(x509=cert_x509_properties(valid=12))
#'
#' }
#' @name certificate
#' @aliases certificate cert
#' @rdname certificate
NULL

stored_cert <- R6::R6Class("stored_cert", inherit=stored_object,

public=list(

    type="certificates",

    id=NULL,
    sid=NULL,
    kid=NULL,
    cer=NULL,
    x5t=NULL,
    contentType=NULL,
    pending=NULL,
    policy=NULL,

    export=function(file)
    {
        if(is.character(file))
        {
            file <- file(file, "wb")
            on.exit(close(file))
        }

        secret <- call_vault_url(self$token, self$sid)
        value <- if(secret$contentType == "application/x-pkcs12")
            openssl::base64_decode(secret$value)
        else charToRaw(secret$value)

        writeBin(value, file)
    },

    sync=function()
    {
        pending <- call_vault_url(self$token, self$pending$id)
        if(pending$status == "completed" && !is_empty(pending$target))
        {
            props <- call_vault_url(self$token, pending$target)
            self$initialize(self$token, self$url, self$name, NULL, props)
        }
        self
    },

    list_versions=function()
    {
        lst <- lapply(get_vault_paged_list(self$do_operation("versions", version=NULL), self$token), function(props)
        {
            attr <- props$attributes
            data.frame(
                version=basename(props$id),
                thumbprint=props$x5t,
                created=int_to_date(attr$created),
                updated=int_to_date(attr$updated),
                expiry=int_to_date(attr$exp),
                not_before=int_to_date(attr$nbf),
                stringsAsFactors=FALSE
            )
        })
        do.call(rbind, lst)
    },

    get_policy=function()
    {
        op <- construct_path(self$name, "policy")
        self$do_operation(op, version=NULL)
    },

    set_policy=function(subject=NULL, x509=NULL, issuer=NULL,
                        key=NULL, secret_type=NULL, actions=NULL,
                        attributes=NULL, wait=TRUE)
    {
        if(!is.null(secret_type))
        {
            secret_type <- if(secret_type == "pem")
                "application/x-pem-file"
            else "application/x-pkcs12"
        }

        policy <- list(
            issuer=issuer,
            key_props=key,
            secret_props=list(contentType=secret_type),
            x509_props=c(subject=subject, x509),
            lifetime_actions=actions
        )

        body <- list(policy=compact(policy), attributes=attributes)

        op <- construct_path(self$name, "policy")
        pol <- self$do_operation(op, body=body, encode="json", version=NULL, http_verb="PATCH")
        self$policy <- pol
        pol
    }
))
