# Password CSV Merge

Merge two password exports locally, preserving the rows and metadata of a **base CSV**. Review conflicting passwords one at a time with a single key, or automatically use the incoming version.

The script never modifies either source file or changes a live password manager. It writes one new CSV for you to import yourself.

## Requirements

- Python 3.8 or newer; no third-party packages.
- macOS or Linux. Interactive review requires an ANSI-compatible terminal.
- UTF-8 CSV exports with `URL`, `Username`, and `Password` columns. Header names are case-insensitive. Comma, semicolon, and tab delimiters are accepted.

On macOS, file pickers appear if you omit paths. On Linux, supply paths or use the terminal prompts. `python3 --version` checks your Python installation.

## Quick start

Save `password_csv_merge.py`, then run:

```bash
python3 password_csv_merge.py --review
```

Choose the **incoming** CSV, the **base** CSV, and—after reviewing—a new output filename. The base determines the output columns, row order, and retained metadata.

For Apple as the base and Chrome as the incoming source:

```bash
python3 password_csv_merge.py \
  --review \
  --base-label Apple \
  --incoming-label Chrome
```

Each screen shows the site, username, **base password in yellow**, and **incoming password in green**.

| Key | Action |
| --- | --- |
| **1** | Keep the base password and advance |
| **2** | Use the incoming password and advance |
| **B** | Go back and revise a choice |
| **Q** | Cancel; no output CSV is written |
| **Space / P** | Next / previous page if a very long entry needs multiple pages |
| **Enter** | Finish and save on the final review screen |

No Enter is needed for individual choices. The older **A** and **C** shortcuts still work as aliases for **1** and **2**. Identical passwords and base-only entries do not need review. Decisions stay in memory; quitting does not save a partial review or a resume file.

## What is preserved

- Every base row, in its original order.
- Base column names and order.
- Every non-password value in existing base rows, including titles, notes, `OTPAuth`, and unknown extra columns.
- Base-only logins and passwords you choose to keep during review.
- Both original CSV files, unchanged.

By default, incoming-only logins are **not added**. Include `--add-incoming-only` to append them. For appended rows, matching columns are copied; `name` ↔ `Title` and `note` ↔ `Notes` are mapped automatically. Base columns with no incoming equivalent stay empty. This column mapping applies only to new rows; existing base metadata is never replaced.

The output is UTF-8 with a BOM, comma-separated, and uses CRLF record separators. It is reread to verify the header and all cell values. The script refuses to overwrite an existing output file and creates the new file with owner-only permissions (`0600`).

## Matching rules

Matching uses the exact, case-sensitive username. Username whitespace is significant.

1. Try a normalized full URL plus username.
2. If no full-URL match exists, try the same hostname and non-default port plus username.

Hostnames are case-insensitive. URL paths and query strings remain significant for full-URL matching; fragments are ignored. Default HTTP/HTTPS ports are normalized. Host fallback allows differing login paths and HTTP/HTTPS URLs on the same host, but does **not** combine subdomains, `www.` with the bare domain, or different non-default ports.

If incoming candidates have different passwords, an exact URL match can resolve the difference. Otherwise, the base row stays unchanged and appears in the ambiguity count. An empty incoming password never replaces a base password. Non-web URLs support exact-string matching only; a blank URL does not match.

For full-URL matching without host fallback, use:

```bash
python3 password_csv_merge.py --review --match exact
```

Counts refer to CSV rows, not necessarily unique accounts in a password manager. Duplicate base rows are preserved. Ambiguous rows are not included in the interactive review; resolve the source ambiguity separately and rerun if necessary.

## Example: Chrome → Apple Passwords

Apple's CSV importer does not overwrite existing passwords. This workflow prepares a complete CSV first, then replaces the corresponding saved password records through Apple's interface.

### 1. Export Chrome passwords

Create a private working folder, keeping it outside your code repository:

```bash
mkdir -m 700 "$HOME/password-merge-work"
```

If that folder already exists, use it or choose a different private folder.

In Chrome, open **Google Password Manager → Settings**. Under **Export passwords**, choose **Download file** and authenticate if prompted. Save it as `chrome.csv` in a private local working folder outside your Git repository.

You can open the settings page directly with:

```text
chrome://password-manager/settings
```

Typical Chrome columns:

```csv
name,url,username,password,note
```

### 2. Export Apple passwords and retain the backup

Open and unlock **Passwords** on your Mac. Choose **File → Export All Passwords to File** and save `apple.csv` in the same private working folder. Keep this original export as your backup until you have verified the replacement.

Typical Apple columns:

```csv
Title,URL,Username,Password,Notes,OTPAuth
```

**A password CSV is not a complete backup of the Passwords app.** Passkeys, shared-group membership, password history, and other app-specific state are not reconstructed by this script. Apple's export also excludes Wi-Fi passwords, some shared passwords, and access to Sign in with Apple accounts. Protect any credentials or state outside the export before deleting anything. The script preserves `OTPAuth` values present in the base CSV; verify that your eventual import restores verification codes correctly.

### 3. Review and merge

Run this from the directory containing the script, replacing the paths with your local files:

```bash
python3 password_csv_merge.py \
  --base "$HOME/password-merge-work/apple.csv" \
  --incoming "$HOME/password-merge-work/chrome.csv" \
  --output "$HOME/password-merge-work/apple-merged.csv" \
  --base-label Apple \
  --incoming-label Chrome \
  --review \
  --add-incoming-only
```

Press **1** for Apple or **2** for Chrome on each difference. Press **B** to correct a previous choice. At the final screen, press **Enter** to create the merged CSV.

`--add-incoming-only` includes logins that exist only in Chrome, so this example combines both collections. Omit it if you want to update existing Apple rows only.

The terminal reports how many rows were matched, replaced, retained, ambiguous, skipped, or added. Verify the totals and investigate any skipped or ambiguous entries **before deleting live records**. The output retains every Apple-export row; without additions its row count equals the original Apple CSV's row count.

For example, with synthetic data:

| Account | Your choice | Result |
| --- | --- | --- |
| `example.com`, `alice` | Keep Apple | Original Apple password |
| `example.net`, `bob` | Use Chrome | Chrome password; Apple notes and OTP retained |
| Apple-only account | No review needed | Original Apple row retained |
| Chrome-only account | `--add-incoming-only` enabled | Appended to the output |

### 4. Delete only the password records you will replace

Do this only after the new CSV has been created and verified, and the original Apple backup is safely retained.

In **Passwords**, select the existing password records represented in your merged export. Choose **Edit → Delete** and confirm. **⌘A** selects the whole visible list: use it only if every selected entry is intended for replacement and you have protected passkeys, shared credentials, and other data outside the CSV. Do not blindly delete the entire **All** collection when it contains those items.

Deletion can sync through iCloud Keychain to your other devices. Leave **Deleted** intact while validating the import; do not permanently purge the old entries at this stage. If you cannot safely isolate the exportable password records, stop before deletion and use a targeted approach instead.

### 5. Import the merged CSV

In **Passwords**, choose **File → Import Passwords from File**, select `apple-merged.csv`, and complete the import.

Check the import result and test representative logins: one kept from Apple, one replaced from Chrome, an Apple-only login, and any newly added Chrome-only login. Also check notes and verification codes you rely on. If something is wrong, keep the original exports and use Apple's **Deleted → Recover** workflow or the original Apple CSV as appropriate. Do not discard your backup until the collection is verified.

### 6. Handle the plaintext files

Both exports and the merged CSV contain plaintext passwords. After successful verification, remove unneeded copies. If retaining a backup, protect it with encryption and restricted access. Avoid leaving these files in shared folders, cloud-synced working directories, screenshots, or Git history. Ordinary file deletion does not guarantee that every historical copy, backup, or storage block has been erased.

## Other modes

Without `--review`, every unambiguous matching password is automatically replaced by the incoming version:

```bash
python3 password_csv_merge.py \
  --base base.csv --incoming incoming.csv --output merged.csv
```

To display old and new passwords after an automatic merge:

```bash
python3 password_csv_merge.py \
  --base base.csv --incoming incoming.csv --output merged.csv \
  --show-passwords
```

The password display is paged and clears when dismissed. Review and password-display modes require a direct interactive terminal and refuse pipes or redirected input/output. Regular summaries include sites and usernames, but not password values.

Use `python3 password_csv_merge.py --help` for all options. Legacy `--apple`, `--chrome`, and `--add-chrome-only` remain aliases for `--base`, `--incoming`, and `--add-incoming-only`.

## Privacy and limits

The script makes no network calls, uploads nothing, uses no clipboard, and writes no password logs or decision files. The only credential file it creates is the requested merged CSV. Passwords remain in process memory while it runs. Interactive screens use a cleared alternate terminal buffer and disable key echo.

Those measures **cannot prevent external monitoring**, screen capture, terminal recording, terminal settings that retain alternate-screen contents, operating-system swap, or backups of your working folder. They are not a guarantee that credentials are never stored anywhere. The script does not automate deletion or importing and does not decide which password is actually current.

Keep credential files outside the repository. Upload only the script, this README, and any deliberately synthetic tests. A Git ignore rule for local CSVs is useful, but it does not remove files already committed:

```gitignore
*.csv
__pycache__/
```

## References

- [Google: Import or export passwords](https://support.google.com/chrome/answer/13068232?hl=en)
- [Apple: Export passwords from your Mac](https://support.apple.com/guide/passwords/export-passwords-mchl35b12625/mac)
- [Apple: Import passwords from another app](https://support.apple.com/guide/passwords/import-passwords-mchl2f1a184c/mac)
- [Apple: Recover a recently deleted password or passkey](https://support.apple.com/guide/passwords/mchlee73013a/mac)
- [1Password: Delete iCloud passwords through the Passwords app](https://support.1password.com/import-safari/#step-4-delete-your-icloud-passwords)

The CSV matching, preservation, review choices, cancellation, output permissions, and terminal cleanup were tested using synthetic credentials, including a 550-update case. The tests do not establish that every macOS version will import every exported credential type without changes; check the actual import result.
