#' Encryption key object
#'
#' This class represents an encryption keys stored in a vault. It provides methods for carrying out operations, including encryption and decryption, signing and verification, and wrapping and unwrapping.
#'
#' @docType class
#'
#' @section Methods:
#' This class provides the following methods:
#' ```
#' encrypt(plaintext, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"))
#' decrypt(ciphertext, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"), as_raw=TRUE)
#' sign(digest,
#'      algorithm=c("PS256", "PS384", "PS512", "RS256", "RS384", "RS512",
#'                  "ES256", "ES256K", "ES384", "ES512"))
#' verify(signature, digest,
#'        algorithm=c("PS256", "PS384", "PS512", "RS256", "RS384", "RS512",
#'                    "ES256", "ES256K", "ES384", "ES512"))
#' wrap(value, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"))
#' unwrap(value, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"), as_raw=TRUE)
#'
#' update_attributes(attributes=vault_object_attrs(), ...)
#' list_versions()
#' set_version(version=NULL)
#' delete(confirm=TRUE)
#' ```
#' @section Arguments:
#' - `plaintext`: For `encrypt`, the plaintext to encrypt.
#' - `ciphertext`: For `decrypt`, the ciphertext to decrypt.
#' - `digest`: For `sign`, a generated hash to sign. For `verify`, the digest to verify for authenticity.
#' - `signature`: For `verify`, a signature to verify for authenticity.
#' - `value`: For `wrap`, a symmetric key to be wrapped; for `unwrap`, the value to be unwrapped to obtain the symmetric key.
#' - `as_raw`: For `decrypt` and `unwrap`, whether to return a character vector or a raw vector (the default).
#' - `algorithm`: The algorithm to use for each operation. Note that the operation must be compatible with the key type.
#' - `attributes`: For `update_attributes`, the new attributes for the object, such as the expiry date and activation date. A convenient way to provide this is via the [vault_object_attrs] helper function.
#' - `...`: For `update_attributes`, additional key-specific properties to update. See [keys].
#' - `version`: For `set_version`, the version ID or NULL for the current version.
#' - `confirm`: For `delete`, whether to ask for confirmation before deleting the key.
#'
#' @section Details:
#' The operations supported by a key will be those given by the `key_ops` argument when the key was created. By default, a new key supports all the operations listed above: encrypt/decrypt, sign/verify, and wrap/unwrap.
#'
#' A key can have multiple _versions_, which are automatically generated when a key is created with the same name as an existing key. By default, the most recent (current) version is used for key operations; use `list_versions` and `set_version` to change the version.
#'
#' @section Value:
#' For the key operations, a raw vector (for `decrypt` and `unwrap`, if `as_raw=TRUE`) or character vector.
#'
#' For `list`, a vector of key version IDs.
#'
#' For `set_version`, the key object with the updated version.
#'
#' @seealso
#' [keys]
#'
#' [Azure Key Vault documentation](https://docs.microsoft.com/en-us/azure/key-vault/),
#' [Azure Key Vault API reference](https://docs.microsoft.com/en-us/rest/api/keyvault)
#'
#' @examples
#' \dontrun{
#'
#' vault <- key_vault$new("mykeyvault")
#'
#' vault$keys$create("mynewkey")
#' # new version of an existing key
#' vault$keys$create("mynewkey", key_properties(type="RSA", rsa_key_size=4096))
#'
#' key <- vault$keys$get("mynewkey")
#' vers <- key$list_versions()
#' key$set_version(vers[2])
#'
#' plaintext <- "some secret text"
#'
#' ciphertext <- key$encrypt(plaintext)
#' decrypted <- key$decrypt(ciphertext, as_raw=FALSE)
#' decrypted == plaintext  # TRUE
#'
#' dig <- digest::digest(plaintext, "sha256", raw=TRUE)
#' sig <- key$sign(dig)
#' key$verify(sig, dig)  # TRUE
#' 
#' wraptext <- key$wrap(plaintext)
#' unwrap_text <- key$unwrap(wraptext, as_raw=FALSE)
#' plaintext == unwrap_text  # TRUE
#'
#' }
#' @name keys
#' @rdname keys
NULL

stored_key <- R6::R6Class("stored_key", inherit=stored_object,

public=list(

    type="keys",

    key=NULL,

    list_versions=function()
    {
        lst <- lapply(get_vault_paged_list(self$do_operation("versions", version=NULL), self$token), function(props)
        {
            attr <- props$attributes
            data.frame(
                version=basename(props$kid),
                created=int_to_date(attr$created),
                updated=int_to_date(attr$updated),
                expiry=int_to_date(attr$exp),
                not_before=int_to_date(attr$nbf),
                stringsAsFactors=FALSE
            )
        })

        do.call(rbind, lst)
    },

    encrypt=function(plaintext, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"))
    {
        if(!is.raw(plaintext) && !is.character(plaintext))
            stop("Can only encrypt raw or character plaintext")

        body <- list(
            alg=match.arg(algorithm),
            value=jose::base64url_encode(plaintext)
        )
        self$do_operation("encrypt", body=body, encode="json", http_verb="POST")$value
    },

    decrypt=function(ciphertext, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"), as_raw=TRUE)
    {
        if(!is.raw(ciphertext) && !is.character(ciphertext))
            stop("Can only decrypt raw or character ciphertext")

        body <- list(
            alg=match.arg(algorithm),
            value=ciphertext
        )
        out <- jose::base64url_decode(
            self$do_operation("decrypt", body=body, encode="json", http_verb="POST")$value)

        if(as_raw) out else rawToChar(out)
    },

    sign=function(digest,
                  algorithm=c("PS256", "PS384", "PS512", "RS256", "RS384", "RS512",
                              "ES256", "ES256K", "ES384", "ES512"))
    {
        if(!is.raw(digest) && !is.character(digest))
            stop("Can only sign raw or character digest")

        body <- list(
            alg=match.arg(algorithm),
            value=jose::base64url_encode(digest)
        )
        self$do_operation("sign", body=body, encode="json", http_verb="POST")$value
    },

    verify=function(signature, digest,
                    algorithm=c("PS256", "PS384", "PS512", "RS256", "RS384", "RS512",
                                "ES256", "ES256K", "ES384", "ES512"))
    {
        if(!is.raw(signature) && !is.character(signature))
            stop("Can only verify raw or character signature")

        if(!is.raw(digest) && !is.character(digest))
            stop("Can only verify raw or character digest")

        body <- list(
            alg=match.arg(algorithm),
            digest=jose::base64url_encode(digest),
            value=signature
        )
        self$do_operation("verify", body=body, encode="json", http_verb="POST")$value
    },

    wrap=function(value, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"))
    {
        if(!is.raw(value) && !is.character(value))
            stop("Can only wrap raw or character input")

        body <- list(
            alg=match.arg(algorithm),
            value=jose::base64url_encode(value)
        )
        self$do_operation("wrapkey", body=body, encode="json", http_verb="POST")$value
    },

    unwrap=function(value, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"), as_raw=TRUE)
    {
        if(!is.raw(value) && !is.character(value))
            stop("Can only wrap raw or character input")

        body <- list(
            alg=match.arg(algorithm),
            value=value
        )
        out <- jose::base64url_decode(
            self$do_operation("unwrapkey", body=body, encode="json", http_verb="POST")$value)

        if(as_raw) out else rawToChar(out)
    }
))
