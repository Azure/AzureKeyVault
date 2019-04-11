stored_key <- R6::R6Class("stored_key",

public=list(

    token=NULL,
    url=NULL,
    name=NULL,
    version=NULL,
    key=NULL,
    attributes=NULL,
    managed=NULL,
    tags=NULL,

    initialize=function(token, url, name, version, properties)
    {
        self$token <- token
        self$url <- url
        self$name <- name
        self$version <- version

        lapply(names(properties), function(n)
        {
            if(exists(n, self))
                self[[n]] <- properties[[n]]
            else warning("Unexpected property: ", n)
        })

        if(is.null(self$version))
            self$version <- basename(self$key$kid)
    },

    encrypt=function(plaintext, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"))
    {
        if(!is.raw(plaintext) && !is.character(plaintext) && length(plaintext) != 1)
            stop("Can only encrypt raw or character plaintext")

        body <- list(
            alg=match.arg(algorithm),
            value=plaintext
        )
        self$do_operation("encrypt", body=body, encode="json", http_verb="POST")$value
    },

    decrypt=function(ciphertext, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"))
    {
        if(!is.raw(ciphertext) && !is.character(ciphertext) && length(ciphertext) != 1)
            stop("Can only decrypt raw or character ciphertext")

        body <- list(
            alg=match.arg(algorithm),
            value=ciphertext
        )
        self$do_operation("decrypt", body=body, encode="json", http_verb="POST")$value
    },

    sign=function(digest,
                  algorithm=c("ES256", "ES256K", "ES384", "ES512", "PS256",
                              "PS384", "PS512", "RS256", "RS384", "RS512"))
    {
        if(!is.raw(digest) && !is.character(digest) && length(digest) != 1)
            stop("Can only sign raw or character digest")

        body <- list(
            alg=match.arg(algorithm),
            value=jose::base64url_encode(digest)
        )
        self$do_operation("sign", body=body, encode="json", http_verb="POST")$value
    },

    verify=function(signature, digest,
                    algorithm=c("ES256", "ES256K", "ES384", "ES512", "PS256",
                                "PS384", "PS512", "RS256", "RS384", "RS512"))
    {
        if(!is.raw(signature) && !is.character(signature) && length(signature) != 1)
            stop("Can only verify raw or character signature")

        if(!is.raw(digest) && !is.character(digest) && length(digest) != 1)
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
        if(!is.raw(value) && !is.character(value) && length(value) != 1)
            stop("Can only wrap raw or character input")

        body <- list(
            alg=match.arg(algorithm),
            value=value
        )
        self$do_operation("wrapkey", body=body, encode="json", http_verb="POST")$value
    },

    unwrap=function(value, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"))
    {
        if(!is.raw(value) && !is.character(value) && length(value) != 1)
            stop("Can only wrap raw or character input")

        body <- list(
            alg=match.arg(algorithm),
            value=value
        )
        self$do_operation("unwrapkey", body=body, encode="json", http_verb="POST")$value
    },

    do_operation=function(op="", ..., options=list())
    {
        url <- self$url
        url$path <- construct_path("keys", self$name, self$version, op)
        url$query <- options
        call_vault_url(self$token, url, ...)
    }
))
