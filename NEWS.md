# AzureKeyVault 1.0.4

- Change maintainer email address.

# AzureKeyVault 1.0.3

- Support the soft-delete feature for Key Vaults. By default, a new vault will be created with soft-deletion enabled, which protects the vault and its contents from accidental/malicious deletion. A soft-deleted vault is held for a retention period (90 days) during which it can be restored. To hard-delete a soft-deleted vault, call the new `purge_key_vault` method, or specify `purge=TRUE` when deleting the vault.

# AzureKeyVault 1.0.2

- Use `utils::askYesNo` for confirmation prompts on R >= 3.5; this fixes a bug in reading the input. As a side-effect, Windows users who are using RGUI.exe will see a popup dialog box instead of a message in the terminal.

# AzureKeyVault 1.0.1

- Allow tokens to be passed to `key_vault` as character strings, as well as objects of class `AzureToken`.
- Better handling of nulls in API calls.

# AzureKeyVault 1.0.0

- Initial CRAN release
