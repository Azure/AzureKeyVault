#' Helper functions for key vault objects
#'
#' @param type For key properties, the type of key to create: RSA or elliptic curve (EC).
#' @param hardware Whether to use a hardware key or software key. The former requires a premium key vault.
#' @param ec_curve For an EC key, the type of elliptic curve.
#' @param rsa_key_size For an RSA key, the key size, either 2048, 3072 or 4096.
#' @param key_exportable For a key used in a certificate, whether it should be exportable.
#' @param reuse_key For a key used in a certificate, whether it should be reused when renewing the certificate.
#' @param dns_names,emails,upns For `cert_x509_properties`, the possible subject alternative names (SANs) for a certificate. These should be character vectors.
#' @param key_usages For `cert_x509_properties`, a character vector of key usages.
#' @param enhanced_key_usages For `cert_x509_properties`, a character vector of enhanced key usages (EKUs).
#' @param valid For `cert_x509_properties`, the number of months the certificate should be valid for.
#' @param issuer For `cert_issuer_properties`, the name of the issuer. Defaults to "self" for a self-signed certificate.
#' @param cert_type For `cert_issuer_properties`, the type of certificate to issue, eg "OV-SSL", "DV-SSL" or "EV-SSL".
#' @param transparent For `cert_issuer_properties`, whether the certificate should be transparent.
#' @param auto_renew For `cert_expiry_actions`, when to automatically renew the certificate. If this is a number between 0 and 1, it is interpreted as the fraction of lifetime remaining; if greater than 1, the number of days remaining.
#' @param email_contacts For `cert_expiry_actions`, when to notify the listed contacts for the key vault that a certificate is about to expire. If this is a number between 0 and 1, it is interpreted as the fraction of lifetime remaining; if greater than 1, the number of days remaining.
#' @param enabled For `vault_object_attrs`, whether this stored object (key, secret, certificate, storage account) is enabled.
#' @param expiry_date,activation_date For `vault_object_attrs`, the optional expiry date and activation date of the stored object. Can be any R object that can be coerced to POSIXct format.
#' @param recovery_level For `vault_object_attrs`, the recovery level for the stored object.
#'
#' @details
#' These are convenience functions for specifying the properties of objects stored in a key vault. They return lists of fields to pass to the REST API.
#'
#' @rdname helpers
#' @export
key_properties <- function(type=c("RSA", "EC"), hardware=FALSE, ec_curve=NULL, rsa_key_size=NULL)
{
    type <- match.arg(type)
    key <- switch(type,
        "RSA"=list(kty=type, key_size=rsa_key_size),
        "EC"=list(kty=type, crv=ec_curve))

    if(hardware)
        type <- paste0(type, "-HSM")

    compact(key)
}


#' @rdname helpers
#' @export
cert_key_properties <- function(type=c("RSA", "EC"), hardware=FALSE, ec_curve=NULL, rsa_key_size=NULL,
                                key_exportable=TRUE, reuse_key=FALSE)
{
    type <- match.arg(type)
    props <- c(key_properties(type, hardware, ec_curve, rsa_key_size), reuse_key=reuse_key, exportable=key_exportable)
    compact(props)
}


#' @rdname helpers
#' @export
cert_x509_properties=function(dns_names=character(), emails=character(), upns=character(),
                              key_usages=character(), enhanced_key_usages=character(), valid=NULL)
{
    sans <- list(dns_names=I(dns_names), emails=I(emails), upns=I(upns))
    props <- list(sans=sans, key_usage=I(key_usages), ekus=I(enhanced_key_usages), validity_months=valid)
    compact(props)
}


#' @rdname helpers
#' @export
cert_issuer_properties=function(issuer="self", cert_type=NULL, transparent=NULL)
{
    compact(list(name=issuer, cty=cert_type, cert_transparency=transparent))
}


#' @rdname helpers
#' @export
cert_expiry_actions <- function(auto_renew=NULL, email_contacts=NULL)
{
    auto_renew <- if(!is.null(auto_renew))
    {
        if(auto_renew < 1)
            list(action="AutoRenew", trigger=list(lifetime_percentage=round(auto_renew*100)))
        else list(action="AutoRenew", trigger=list(days_before_expiry=auto_renew))
    }

    email_contacts <- if(!is.null(email_contacts))
    {
        if(email_contacts < 1)
            list(action="EmailContacts", trigger=list(lifetime_percentage=round(email_contacts*100)))
        else list(action="EmailContacts", trigger=list(days_before_expiry=email_contacts))
    }

    actions <- list(auto_renew, email_contacts)
    compact(actions)
}


#' @rdname helpers
#' @export
vault_object_attrs <- function(enabled=TRUE, expiry_date=NULL, activation_date=NULL, recovery_level=NULL)
{
    attribs <- list(
        enabled=enabled,
        nbf=make_vault_date(activation_date),
        exp=make_vault_date(expiry_date),
        recoveryLevel=recovery_level
    )
    compact(attribs)
}


compact <- function(lst)
{
    lst[!sapply(lst, is.null)]
}


make_vault_date <- function(date)
{
    if(is_empty(date))
        NULL
    else if(inherits(date, "POSIXt"))
        as.numeric(date)
    else as.numeric(as.POSIXct(date))
}


int_to_date <- function(dte)
{
    if(is_empty(dte))
        NA
    else as.POSIXct(dte, origin="1970-01-01")
}

