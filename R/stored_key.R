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
