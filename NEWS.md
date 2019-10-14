# AzureKeyVault 1.0.2

- Use `utils::askYesNo` for confirmation prompts on R >= 3.5; this fixes a bug in reading the input. As a side-effect, Windows users who are using RGUI.exe will see a popup dialog box instead of a message in the terminal.

# AzureKeyVault 1.0.1

- Allow tokens to be passed to `key_vault` as character strings, as well as objects of class `AzureToken`.
- Better handling of nulls in API calls.


# AzureKeyVault 1.0.0

- Initial CRAN release
