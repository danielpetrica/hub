AppSec rule detecting the PHP `session.upload_progress` abuse technique.

With `session.upload_progress.enabled` left on (the PHP default), the name of a
multipart part is used as the session key prefix and its **content** is written
into the session file. An attacker sends:

```http
POST / HTTP/1.1
Host: victim.example
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

pwned
------x
Content-Disposition: form-data; name="file"; filename="sess_test"

<?php system($_GET['c']); ?>
------x--
```

Combined with any local file inclusion (LFI), log poisoning or session-file
including primitive, the attacker-controlled session file contains PHP code and
becomes RCE. This rule detects the presence of the `PHP_SESSION_UPLOAD_PROGRESS`
part name in the multipart body, which no legitimate application uses.

Temporary hardening while the underlying vulnerability is being fixed:

```ini
session.upload_progress.enabled = Off
```
