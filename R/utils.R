call_vault_url <- function(token, url, ..., body=NULL, encode="json",
                           api_version=getOption("azure_keyvault_api_version"),
                           http_verb=c("GET", "DELETE", "PUT", "POST", "HEAD", "PATCH"),
                           http_status_handler=c("stop", "warn", "message", "pass"))
{
    if(!inherits(url, "url"))
        url <- httr::parse_url(url)

    if(is.null(url$query))
        url$query <- list()

    url$query <- utils::modifyList(url$query, list(`api-version`=api_version))
    headers <- process_headers(token, url)

    # if content-type is json, serialize it manually to ensure proper handling of nulls
    if(encode == "json")
    {
        empty <- vapply(body, is_empty, logical(1))
        body <- jsonlite::toJSON(body[!empty], auto_unbox=TRUE, digits=22, null="null")
        encode <- "raw"
    }

    res <- httr::VERB(match.arg(http_verb), url, headers, body=body, encode=encode, ...)
    process_response(res, match.arg(http_status_handler))
}


process_headers <- function(token, url)
{
    headers <- c(
        Host=url$hostname,
        Authorization=paste("Bearer", validate_token(token)),
        `Content-type`="application/json"
    )
    httr::add_headers(.headers=headers)
}


validate_token <- function(token)
{
    # token can be a string or an object of class AzureToken
    if(AzureRMR::is_azure_token(token))
    {
        if(!token$validate()) # refresh if needed
        {
            message("Access token has expired or is no longer valid; refreshing")
            token$refresh()
        }
        token <- token$credentials$access_token
    }
    else if(!is.character(token))
        stop("Invalid authentication token", call.=FALSE)
    token
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

    gsub("\r", "", paste0(strwrap(msg), collapse="\n"))
}


construct_path <- function(...)
{
    args <- list(...)
    args <- args[!sapply(args, is.null)]
    sub("//", "/", do.call(file.path, args))
}


get_vault_paged_list <- function(lst, token, next_link_name="nextLink", value_name="value")
{
    res <- lst[[value_name]]
    while(!is_empty(lst[[next_link_name]]))
    {
        lst <- call_vault_url(token, lst[[next_link_name]])
        res <- c(res, lst[[value_name]])
    }
    res
}


# TRUE if delete confirmed, FALSE otherwise
delete_confirmed <- function(confirm, name, type)
{
    if(!interactive() || !confirm)
        return(TRUE)

    msg <- sprintf("Do you really want to delete the %s '%s'?", type, name)
    ok <- if(getRversion() < numeric_version("3.5.0"))
    {
        msg <- paste(msg, "(yes/No/cancel) ")
        yn <- readline(msg)
        if(nchar(yn) == 0)
            FALSE
        else tolower(substr(yn, 1, 1)) == "y"
    }
    else utils::askYesNo(msg, FALSE)
    isTRUE(ok)
}

