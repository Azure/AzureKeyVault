#' @export
key_properties <- function(type=c("RSA", "RSA-HSM", "EC", "EC-HSM"), ec_curve=NULL, rsa_key_size=NULL)
{
    type <- match.arg(type)
    key <- if(type %in% c("RSA", "RSA-HSM"))
        list(kty=type, key_size=rsa_key_size)
    else if(type %in% c("EC", "EC-HSM"))
        list(kty=type, crv=ec_curve)
    compact(key)
}


#' @export
cert_key_properties <- function(type=c("RSA", "RSA-HSM", "EC", "EC-HSM"), ec_curve=NULL, rsa_key_size=NULL,
                                key_exportable=TRUE, reuse_key=FALSE)
{
    props <- c(key_properties(type, ec_curve, rsa_key_size), reuse_key=reuse_key, exportable=key_exportable)
    compact(props)
}


#' @export
cert_x509_properties=function(dns_names=character(), emails=character(), upns=character(),
                              key_usages=character(), enhanced_key_usages=character(), valid=NULL)
{
    sans <- list(dns_names=I(dns_names), emails=I(emails), upns=I(upns))
    props <- list(sans=sans, key_usage=I(key_usages), ekus=I(enhanced_key_usages), validity_months=valid)
    compact(props)
}


#' @export
cert_issuer_properties=function(issuer="self", type=NULL, transparent=NULL)
{
    compact(list(name=issuer, cty=type, cert_transparency=transparent))
}


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


int_to_date <- function(dte)
{
    if(is_empty(dte))
        NA
    else as.POSIXct(dte, origin="1970-01-01")
}

