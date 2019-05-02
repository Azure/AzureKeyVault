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
#' export_cer(file)
#' sign(digest, ...)
#' verify(signature, digest, ...)
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
#' - `file`: For `export` and `export_cer`, a connection object or a character string naming a file to export to.
#' - `digest`: For `sign`, a hash digest string to sign. For `verify`, a digest to compare to a signature.
#' - `signature`: For `verify`, a signature string.
#' - `subject,x509,issuer,key,secret_type,actions,wait`: These are the same arguments as used when creating a new certificate. See [certificates] for more information.
#' - `attributes`: For `update_attributes`, the new attributes for the object, such as the expiry date and activation date. A convenient way to provide this is via the [vault_object_attrs] helper function.
#' - `...`: For `update_attributes`, additional key-specific properties to update. For `sign` and `verify`, additional arguments for the corresponding key object methods. See [keys] and [key].
#' - `version`: For `set_version`, the version ID or NULL for the current version.
#' - `confirm`: For `delete`, whether to ask for confirmation before deleting the key.
#'
#' @section Details:
#' `export` exports the full certificate to a file. The format wll be either PEM or PFX (aka PKCS#12), as set by the `format` argument when the certificate was created. `export_cer` exports the public key component, aka the CER file. Note that the public key can also be found in the `cer` field of the object.
#'
#' `sign` uses the key associated with the a certificate to sign a digest, and `verify` checks a signature against a digest for authenticity. See below for an example of using `sign` to do OAuth authentication with certificate credentials.
#'
#' `set_policy` updates the authentication details of a certificate: its issuer, identity, key type, renewal actions, and so on. `get_policy` returns the current policy of a certificate.
#'
#' A certificate can have multiple _versions_, which are automatically generated when a cert is created with the same name as an existing cert. By default, this object contains the information for the most recent (current) version; use `list_versions` and `set_version` to change the version.
#'
#' @section Value:
#' For `get_policy`, a list of certificate policy details.
#'
#' For `list_versions`, a data frame containing details of each version.
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
#' vault <- key_vault("mykeyvault")
#'
#' cert <- vault$certificates$create("mynewcert")
#' cert$cer
#' cert$export("mynewcert.pem")
#'
#' # new version of an existing certificate
#' vault$certificates$create("mynewcert", x509=cert_x509_properties(validity_months=24))
#'
#' cert <- vault$certificates$get("mynewcert")
#' vers <- cert$list_versions()
#' cert$set_version(vers[2])
#'
#' # updating an existing cert version
#' cert$set_policy(x509=cert_x509_properties(validity_months=12))
#'
#'
#' ## signing a JSON web token (JWT) for authenticating with Azure Active Directory
#' app <- "app_id"
#' tenant <- "tenant_id"
#' claim <- jose::jwt_claim(
#'     iss=app,
#'     sub=app,
#'     aud="https://login.microsoftonline.com/tenant_id/oauth2/token",
#'     exp=as.numeric(Sys.time() + 60*60),
#'     nbf=as.numeric(Sys.time())
#' )
#' # header includes cert thumbprint
#' header <- list(alg="RS256", typ="JWT", x5t=cert$x5t)
#'
#' token_encode <- function(x)
#' {
#'     jose::base64url_encode(jsonlite::toJSON(x, auto_unbox=TRUE))
#' }
#' token_contents <- paste(token_encode(header), token_encode(claim), sep=".")
#'
#' # get the signature and concatenate it with header and claim to form JWT
#' sig <- cert$sign(openssl::sha256(charToRaw(token_contents)))
#' cert_creds <- paste(token_contents, sig, sep=".")
#'
#' AzureAuth::get_azure_token("resource_url", tenant, app, certificate=cert_creds)
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

    export_cer=function(file)
    {
        if(is.character(file))
        {
            file <- file(file, "wb")
            on.exit(close(file))
        }
        writeLines(self$cer, file)
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
        structure(self$do_operation("policy", version=NULL), class="cert_policy")
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

        pol <- self$do_operation("policy", body=body, encode="json", version=NULL, http_verb="PATCH")
        self$policy <- pol
        structure(pol, class="cert_policy")
    },

    sign=function(digest, ...)
    {
        key <- stored_key$new(self$token, self$url, self$name, NULL,
            call_vault_url(self$token, self$kid))
        key$sign(digest, ...)
    },

    verify=function(signature, digest, ...)
    {
        key <- stored_key$new(self$token, self$url, self$name, NULL,
            call_vault_url(self$token, self$kid))
        key$verify(signature, digest, ...)
    },

    print=function(...)
    {
        cat("<certificate '", self$name, "'>\n", sep="")
        cat("  version:", if(is.null(self$version)) "<default>" else self$version, "\n")
        cat("  subject:", self$policy$x509_props$subject, "\n")
        cat("  issuer:", self$policy$issuer$name, "\n")
        cat("  valid for:", self$policy$x509_props$validity_months, "months\n")
        invisible(self)
    }
))


#' @export
print.cert_policy <- function(x, ...)
{
    out <- lapply(x[-1], data.frame)  # remove ID, use data.frame for printing
    names(out$x509_props) <- names(unlist(x$x509_props))  # fixup names for x509_props

    mapply(function(name, value)
    {
        cat(name, ":\n", sep="")
        print(value, row.names=FALSE)
        cat("\n")
    }, names(out), out)

    invisible(x)
}
