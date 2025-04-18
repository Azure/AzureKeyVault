% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/stored_cert.R
\docType{class}
\name{certificate}
\alias{certificate}
\alias{cert}
\title{Certificate object}
\description{
This class represents a certificate stored in a vault. It provides methods for carrying out operations, including encryption and decryption, signing and verification, and wrapping and unwrapping.
}
\section{Fields}{

This class provides the following fields:
\itemize{
\item \code{cer}: The contents of the certificate, in CER format.
\item \code{id}: The ID of the certificate.
\item \code{kid}: The ID of the key backing the certificate.
\item \code{sid}: The ID of the secret backing the certificate.
\item \code{contentType}: The content type of the secret backing the certificate.
\item \code{policy}: The certificate management policy, containing the authentication details.
\item \code{x5t}: The thumbprint of the certificate.
}
}

\section{Methods}{

This class provides the following methods:

\if{html}{\out{<div class="sourceCode">}}\preformatted{export(file)
export_cer(file)
sign(digest, ...)
verify(signature, digest, ...)
set_policy(subject=NULL, x509=NULL, issuer=NULL,
           key=NULL, secret_type=NULL, actions=NULL,
           attributes=NULL, wait=TRUE)
get_policy()
sync()

update_attributes(attributes=vault_object_attrs(), ...)
list_versions()
set_version(version=NULL)
delete(confirm=TRUE)
}\if{html}{\out{</div>}}
}

\section{Arguments}{

\itemize{
\item \code{file}: For \code{export} and \code{export_cer}, a connection object or a character string naming a file to export to.
\item \code{digest}: For \code{sign}, a hash digest string to sign. For \code{verify}, a digest to compare to a signature.
\item \code{signature}: For \code{verify}, a signature string.
\item \verb{subject,x509,issuer,key,secret_type,actions,wait}: These are the same arguments as used when creating a new certificate. See \link{certificates} for more information.
\item \code{attributes}: For \code{update_attributes}, the new attributes for the object, such as the expiry date and activation date. A convenient way to provide this is via the \link{vault_object_attrs} helper function.
\item \code{...}: For \code{update_attributes}, additional key-specific properties to update. For \code{sign} and \code{verify}, additional arguments for the corresponding key object methods. See \link{keys} and \link{key}.
\item \code{version}: For \code{set_version}, the version ID or NULL for the current version.
\item \code{confirm}: For \code{delete}, whether to ask for confirmation before deleting the key.
}
}

\section{Details}{

\code{export} exports the full certificate to a file. The format wll be either PEM or PFX (aka PKCS#12), as set by the \code{format} argument when the certificate was created. \code{export_cer} exports the public key component, aka the CER file. Note that the public key can also be found in the \code{cer} field of the object.

\code{sign} uses the key associated with the a certificate to sign a digest, and \code{verify} checks a signature against a digest for authenticity. See below for an example of using \code{sign} to do OAuth authentication with certificate credentials.

\code{set_policy} updates the authentication details of a certificate: its issuer, identity, key type, renewal actions, and so on. \code{get_policy} returns the current policy of a certificate.

A certificate can have multiple \emph{versions}, which are automatically generated when a cert is created with the same name as an existing cert. By default, this object contains the information for the most recent (current) version; use \code{list_versions} and \code{set_version} to change the version.
}

\section{Value}{

For \code{get_policy}, a list of certificate policy details.

For \code{list_versions}, a data frame containing details of each version.

For \code{set_version}, the key object with the updated version.
}

\examples{
\dontrun{

vault <- key_vault("mykeyvault")

cert <- vault$certificates$create("mynewcert")
cert$cer
cert$export("mynewcert.pem")

# new version of an existing certificate
vault$certificates$create("mynewcert", x509=cert_x509_properties(validity_months=24))

cert <- vault$certificates$get("mynewcert")
vers <- cert$list_versions()
cert$set_version(vers[2])

# updating an existing cert version
cert$set_policy(x509=cert_x509_properties(validity_months=12))


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

}
}
\seealso{
\link{certificates}

\href{https://learn.microsoft.com/en-us/azure/key-vault/}{Azure Key Vault documentation},
\href{https://learn.microsoft.com/en-us/rest/api/keyvault}{Azure Key Vault API reference}
}
