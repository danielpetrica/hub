# danielpetrica/php-upload-progress

Detection package for the PHP `session.upload_progress` abuse technique and the
PHP wrapper / ini-injection probes that usually come with it.

## What it installs

| Type | Item | Detects |
|---|---|---|
| scenario | `danielpetrica/php-upload-progress-probe` | URL-visible payloads (`php://filter`, `auto_prepend_file`, `php-cgi`, `%AD%AD`) in access logs |
| appsec-config | `danielpetrica/php-upload-progress` | in-band blocking, default remediation `ban` |
| appsec-rule | `danielpetrica/php-upload-progress` | multipart body containing the `PHP_SESSION_UPLOAD_PROGRESS` part |
| appsec-rule | `danielpetrica/php-ini-injection-probe` | PHP wrapper / ini directive injection probes |
| appsec-rule | `danielpetrica/php2shell-user-agent` | `php2shell-<digits>` user-agent used by commodity exploitation kits |

## Background

With `session.upload_progress.enabled` on (the PHP default), the name of a
multipart form part becomes the session key prefix and its content is written
into the session file. Sending `PHP_SESSION_UPLOAD_PROGRESS` with a payload
therefore makes an attacker-controlled "PHP file" appear wherever sessions are
stored. Combined with any LFI or log-poisoning primitive, that is a one-shot
RCE. Partial mitigations, available right now:

```ini
session.upload_progress.enabled = Off
```

## Acquisition (log scenario)

```yaml
filenames:
  - /var/log/traefik/access.log
labels:
  type: traefik
```

The AppSec part requires an AppSec-aware remediation component, e.g. the
Traefik crowdsec bouncer plugin with `crowdsecAppsecEnabled: true`.
