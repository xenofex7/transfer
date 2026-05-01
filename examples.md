# Examples

A collection of patterns beyond the quick-start in [`README.md`](README.md).
All snippets assume an instance reachable at `https://your-instance.example.com`
- swap that for whatever hostname your fork is deployed under.

## Table of Contents

- [Shell helpers](#shell-helpers)
- [Other upload clients](#other-upload-clients)
- [Archives and backups](#archives-and-backups)
- [Encryption](#encryption)
- [Virus scanning](#virus-scanning)
- [Capturing the URL and delete token](#capturing-the-url-and-delete-token)

---

## Shell helpers

### Bash / Zsh

```bash
transfer() {
    if [ $# -eq 0 ]; then
        echo "Usage: transfer <file>"
        return 1
    fi
    curl --progress-bar --upload-file "$1" \
        "https://your-instance.example.com/$(basename "$1")"
    echo
}
```

### Fish

```fish
function transfer --description 'Upload a file'
    if test (count $argv) -eq 0
        echo "Usage: transfer FILE"
        return 1
    end
    curl --progress-bar --upload-file $argv[1] \
        "https://your-instance.example.com/"(basename $argv[1])
    echo
end
funcsave transfer
```

### Windows (CMD + PowerShell)

Save as `transfer.cmd` in your `PATH`:

```cmd
@echo off
setlocal
set FN=%~nx1
set FULL=%1
powershell -noprofile -command "$(Invoke-WebRequest -Method PUT -InFile $Env:FULL https://your-instance.example.com/$Env:FN).Content"
```

---

## Other upload clients

### wget

```bash
wget --method PUT --body-file=/tmp/file.tar \
     -O - -nv \
     https://your-instance.example.com/file.tar
```

### PowerShell

```powershell
Invoke-WebRequest -Method Put -InFile .\file.txt `
                  -Uri https://your-instance.example.com/file.txt
```

### HTTPie

```bash
http PUT https://your-instance.example.com/test.log < /tmp/test.log
```

### Pipe arbitrary stdout

```bash
grep ERROR /var/log/syslog \
  | curl --upload-file - https://your-instance.example.com/errors.log
```

---

## Archives and backups

### Encrypt and ship a MySQL dump

```bash
mysqldump --all-databases \
  | gzip \
  | gpg -ac -o- \
  | curl -X PUT --upload-file - https://your-instance.example.com/dump.sql.gz.gpg
```

### Tar a directory and upload in one shot

```bash
tar -czf - /var/log/journal \
  | curl --upload-file - https://your-instance.example.com/journal.tar.gz
```

### Multiple files in a single request

```bash
curl -i \
  -F filedata=@/tmp/hello.txt \
  -F filedata=@/tmp/hello2.txt \
  https://your-instance.example.com/
```

### Bundle multiple uploads as a download archive

The server can stream a `.zip`, `.tar` or `.tar.gz` of any combination of
existing tokens:

```bash
curl https://your-instance.example.com/(15HKz/hello.txt,7AbcD/notes.md).tar.gz \
  -o bundle.tar.gz
```

### Mail the resulting URL

```bash
transfer /tmp/report.pdf | mail -s "Today's report" team@example.com
```

---

## Encryption

### Symmetric encryption with GPG

```bash
gpg --armor --symmetric --output - /tmp/hello.txt \
  | curl --upload-file - https://your-instance.example.com/hello.txt.asc
```

Decrypt:

```bash
curl https://your-instance.example.com/<token>/hello.txt.asc \
  | gpg --decrypt --output /tmp/hello.txt
```

### Encrypt + cap downloads in one helper

```bash
transfer-encrypted() {
    if [ $# -eq 0 ]; then
        echo "Usage: transfer-encrypted [-D max-downloads] <file>"
        return 1
    fi

    local max_downloads=1
    while getopts ":D:" opt; do
        case $opt in
            D) max_downloads=$OPTARG ;;
            \?) echo "Invalid option: -$OPTARG" >&2 ;;
        esac
    done
    shift "$((OPTIND - 1))"

    local file="$1"
    local file_name
    file_name="$(basename "$file")"

    if [ ! -f "$file" ]; then
        echo "$file: not a regular file" >&2
        return 1
    fi

    openssl aes-256-cbc -pbkdf2 -e -in "$file" \
      | curl -H "Max-Downloads: $max_downloads" \
             --upload-file - \
             "https://your-instance.example.com/$file_name"
    echo
}
```

Decrypt the result:

```bash
curl -s https://your-instance.example.com/<token>/<file> \
  | openssl aes-256-cbc -pbkdf2 -d > <file>
```

### Keybase

```bash
cat backup.tar.gz \
  | keybase encrypt alice bob \
  | curl --upload-file - https://your-instance.example.com/backup.tar.gz.kb

curl https://your-instance.example.com/<token>/backup.tar.gz.kb | keybase decrypt
```

---

## Virus scanning

The instance exposes a synchronous scan endpoint that returns the ClamAV
status without persisting anything. Useful as a one-shot check.

```bash
# EICAR test file - safe, but recognised by every AV
wget https://secure.eicar.org/eicar.com.txt
curl -X PUT --upload-file ./eicar.com.txt \
  https://your-instance.example.com/eicar.com.txt/scan
```

When the regular upload path is configured with `--perform-clamav-prescan`,
infected files are rejected with HTTP 412 (`Precondition Failed`) and the
upload never lands on disk.

---

## Capturing the URL and delete token

Every upload returns the download URL in the response body and the deletion
URL in the `X-Url-Delete` response header. A small wrapper that captures both:

```bash
upload() {
    local file="$1"
    local headers
    headers="$(mktemp)"

    local url
    url="$(curl --silent --progress-bar \
                --dump-header "$headers" \
                --upload-file "$file" \
                "https://your-instance.example.com/$(basename "$file")")"

    local delete_url
    delete_url="$(awk 'tolower($1)=="x-url-delete:" {print $2}' "$headers" | tr -d '\r')"
    rm -f "$headers"

    cat <<INFO
Download:  $url
Delete:    $delete_url
INFO
}
```

Usage:

```bash
$ upload ~/Documents/report.pdf
Download:  https://your-instance.example.com/abc12345/report.pdf
Delete:    https://your-instance.example.com/abc12345/report.pdf/XYZdeleteToken
```
