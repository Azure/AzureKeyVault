call_vault_url <- function(token, url, ...,
                           http_verb=c("GET", "DELETE", "PUT", "POST", "HEAD", "PATCH"),
                           http_status_handler=c("stop", "warn", "message", "pass"))
{
    headers <- process_headers(token, ...)
    res <- httr::VERB(match.arg(http_verb), url, headers, ...)
    process_response(res, match.arg(http_status_handler))
}


process_headers <- function(token, ...)
{
    # if token has expired, renew it
    if(is_azure_token(token) && !token$validate())
    {
        message("Access token has expired or is no longer valid; refreshing")
        token$refresh()
    }

    creds <- token$credentials
    headers <- c(Authorization=paste(creds$token_type, creds$access_token))

    # default content-type is json, set this if encoding not specified
    dots <- list(...)
    if(is_empty(dots) || !("encode" %in% names(dots)) || dots$encode == "raw")
        headers <- c(headers, `Content-type`="application/json")

    httr::add_headers(.headers=headers)
}


process_response <- function(response, handler)
{
    if(handler != "pass")
    {
        cont <- httr::content(response)
        handler <- get(paste0(handler, "_for_status"), getNamespace("httr"))
        handler(response, paste0("complete operation. Message:\n",
                                 sub("\\.$", "", error_message(cont))))

        if(is.null(cont))
            cont <- list()

        attr(cont, "status") <- httr::status_code(response)
        cont
    }
    else response
}


error_message <- function(cont)
{
    # kiboze through possible message locations
    msg <- if(is.character(cont))
        cont
    else if(is.list(cont))
    {
        if(is.character(cont$message))
            cont$message
        else if(is.list(cont$error) && is.character(cont$error$message))
            cont$error$message
        else if(is.list(cont$odata.error))
            cont$odata.error$message$value
    } 
    else ""

    paste0(strwrap(msg), collapse="\n")
}


# handle different behaviour of file_path on Windows/Linux wrt trailing /
construct_path <- function(...)
{
    sub("/$", "", file.path(..., fsep="/"))
}


