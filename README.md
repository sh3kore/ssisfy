# SSISfy

ssisfy is a security tool for inspecting SQL Server Integration Services (SSIS) artifacts, identifying their protection levels, and recovering encrypted content using password candidates or supplied DPAPI artifacts. It extracts connection details, passwords, parameters, variables, and file paths from accessible or decrypted content.

## Installation

Designed to run on Linux with Python 3. Install the dependencies:

```bash
python3 -m pip install pycryptodome impacket
```

## Usage


```bash
python3 ssisfy.py -h
```

ssisfy provides three commands:

| Command | Description |
| --- | --- |
| `fingerprint` | Inspect protection settings, encryption details, and visible metadata. |
| `password` | Test password candidates and decrypt password-protected XML packages. |
| `dpapi` | Decrypt DPAPI-protected packages using supplied offline artifacts. |


All processing uses local files. DPAPI decryption requires the relevant offline artifacts and key material; it can run on Linux without logging in as the Windows user who protected the package.

## Protection levels

| Level | SSIS protection level | Protected content | ssisfy support |
| --- | --- | --- | --- |
| `0` | `DontSaveSensitive` | Sensitive values are not saved | Fingerprinting |
| `1` | `EncryptSensitiveWithUserKey` | Sensitive properties | DPAPI decryption |
| `2` | `EncryptSensitiveWithPassword` | Sensitive properties | Password decryption |
| `3` | `EncryptAllWithPassword` | Entire package | Password decryption |
| `4` | `EncryptAllWithUserKey` | Entire package | DPAPI decryption |
| `5` | `ServerStorage` | Server-managed protection | Recognition only; decryption is not implemented |

## Supported artifacts

| Type | Extensions |
| --- | --- |
| XML artifacts | `.dtsx`, `.params`, `.conmgr`, `.dtproj`, `.database` |
| Containers | `.ispac`, `.zip` |
