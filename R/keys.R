vault_keys <- R6::R6Class("vault_keys", 

public=list(

    token=NULL,
    url=NULL,

    initialize=function(token, url)
    {
        self$token <- token
        self$url <- url
    },

    create=function(name, type=c("RSA", "RSA-HSM", "EC", "EC-HSM"), ec_curve=NULL, rsa_key_size=NULL, key_ops=NULL,
                    enabled=NULL, expiry_date=NULL, activation_date=NULL, recovery_level=NULL, ...)
    {
        type <- match.arg(type)

        attribs <- list(
            enabled=enabled,
            nbf=make_vault_date(activation_date),
            exp=make_vault_date(expiry_date),
            recoveryLevel=recovery_level
        )
        attribs <- attribs[!sapply(attribs, is_empty)]

        body <- list(kty=type, attributes=attribs, key_ops=key_ops, tags=list(...))

        if(type %in% c("RSA", "RSA-HSM"))
            body$key_size=rsa_key_size
        else if(type %in% c("EC", "EC-HSM"))
            body$crv <- ec_curve

        op <- construct_path(name, "create")
        self$do_operation(op, body=body, encode="json", http_verb="POST")
    },

    show=function(name, version=NULL)
    {
        op <- construct_path(name, version)
        self$do_operation(op)
    },

    delete=function(name, confirm=TRUE)
    {
        if(delete_confirmed(confirm, name, "key"))
            self$do_operation(name, http_verb="DELETE")
    },

    list_all=function()
    {
        lst <- get_vault_paged_list(self$do_operation(), self$token)
        names(lst) <- sapply(lst, function(x) basename(x$kid))
        lst
    },

    list_versions=function(name)
    {
        op <- construct_path(name, "versions")
        lst <- get_vault_paged_list(self$do_operation(op), self$token)
        names(lst) <- sapply(lst, function(x) basename(x$kid))
        lst
    },

    backup=function(name)
    {
        self$do_operation(construct_path(name, "backup"), http_verb="POST")$value
    },

    restore=function(name, backup)
    {
        stopifnot(is.character(backup))
        self$do_operation("restore", body=list(value=backup), encode="json", http_verb="POST") 
    },

    encrypt=function(name, plaintext, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"), version=NULL)
    {
        if(!is.raw(plaintext) && !is.character(plaintext) && length(plaintext) != 1)
            stop("Can only encrypt raw or character plaintext")

        op <- construct_path(name, version, "encrypt")
        body <- list(
            alg=match.arg(algorithm),
            value=plaintext
        )
        self$do_operation(op, body=body, encode="json", http_verb="POST")$value
    },

    decrypt=function(name, ciphertext, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"), version=NULL)
    {
        if(!is.raw(ciphertext) && !is.character(ciphertext) && length(ciphertext) != 1)
            stop("Can only decrypt raw or character ciphertext")

        op <- construct_path(name, version, "decrypt")
        body <- list(
            alg=match.arg(algorithm),
            value=ciphertext
        )
        self$do_operation(op, body=body, encode="json", http_verb="POST")$value
    },

    sign=function(name, digest,
                  algorithm=c("ES256", "ES256K", "ES384", "ES512", "PS256",
                              "PS384", "PS512", "RS256", "RS384", "RS512"),
                  version=NULL)
    {
        if(!is.raw(digest) && !is.character(digest) && length(digest) != 1)
            stop("Can only sign raw or character digest")

        op <- construct_path(name, version, "sign")
        body <- list(
            alg=match.arg(algorithm),
            value=digest
        )
        self$do_operation(op, body=body, encode="json", http_verb="POST")$value
    },

    verify=function(name, signature, digest,
                    algorithm=c("ES256", "ES256K", "ES384", "ES512", "PS256",
                                "PS384", "PS512", "RS256", "RS384", "RS512"),
                    version=NULL)
    {
        if(!is.raw(signature) && !is.character(signature) && length(signature) != 1)
            stop("Can only verify raw or character signature")

        if(!is.raw(digest) && !is.character(digest) && length(digest) != 1)
            stop("Can only verify raw or character digest")

        op <- construct_path(name, version, "verify")
        body <- list(
            alg=match.arg(algorithm),
            digest=digest,
            value=signature
        )
        self$do_operation(op, body=body, encode="json", http_verb="POST")$value
    },

    wrap=function(name, value, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"), version=NULL)
    {
        if(!is.raw(value) && !is.character(value) && length(value) != 1)
            stop("Can only wrap raw or character input")

        op <- construct_path(name, version, "wrapkey")
        body <- list(
            alg=match.arg(algorithm),
            value=value
        )
        self$do_operation(op, body=body, encode="json", http_verb="POST")$value
    },

    unwrap=function(name, value, algorithm=c("RSA-OAEP", "RSA-OAEP-256", "RSA1_5"), version=NULL)
    {
        if(!is.raw(value) && !is.character(value) && length(value) != 1)
            stop("Can only wrap raw or character input")

        op <- construct_path(name, version, "unwrapkey")
        body <- list(
            alg=match.arg(algorithm),
            value=value
        )
        self$do_operation(op, body=body, encode="json", http_verb="POST")$value
    },

    import=function(name, key, hardware=FALSE,
                    enabled=NULL, expiry_date=NULL, activation_date=NULL, recovery_level=NULL, ...)
    {
        # support importing keys from openssl package, or as json text
        if(inherits(key, "key"))
            key <- jsonlite::fromJSON(jose::write_jwk(key))
        else if(is.character(key) && jsonlite::validate(key))
            key <- jsonlite::fromJSON(key)

        attribs <- list(
            enabled=enabled,
            nbf=make_vault_date(activation_date),
            exp=make_vault_date(expiry_date),
            recoveryLevel=recovery_level
        )
        attribs <- attribs[!sapply(attribs, is_empty)]

        body <- list(key=key, hsm=hardware, attributes=attribs, tags=list(...))
        self$do_operation(name, body=body, encode="json", http_verb="PUT")
    },

    do_operation=function(op="", ..., options=list(),
                          api_version=getOption("azure_keyvault_api_version"))
    {
        url <- self$url
        url$path <- construct_path("keys", op)
        url$query <- utils::modifyList(list(`api-version`=api_version), options)

        call_vault_url(self$token, url, ...)
    }
))

