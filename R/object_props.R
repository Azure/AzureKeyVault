vault_key_properties <- function(type=c("RSA", "RSA-HSM", "EC", "EC-HSM"), ec_curve=NULL, rsa_key_size=NULL)
{
    type <- match.arg(type)
    if(type %in% c("RSA", "RSA-HSM"))
        list(kty=type, key_size=rsa_key_size)
    else if(type %in% c("EC", "EC-HSM"))
        list(kty=type, crv=ec_curve)
}


vault_object_attrs <- function(enabled=TRUE, expiry_date=NULL, activation_date=NULL, recovery_level=NULL)
{
    attribs <- list(
        enabled=enabled,
        nbf=make_vault_date(activation_date),
        exp=make_vault_date(expiry_date),
        recoveryLevel=recovery_level
    )
    attribs[!sapply(attribs, is_empty)]
}
