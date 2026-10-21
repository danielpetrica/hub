# danielpetrica/php-upload-progress

In-band AppSec configuration for the PHP `session.upload_progress` abuse chain.

Loads `crowdsecurity/base-config` (required to decode
`application/x-www-form-urlencoded` and `multipart/form-data` bodies) plus:

- `danielpetrica/php-upload-progress` - the `PHP_SESSION_UPLOAD_PROGRESS`
  multipart signature
- `danielpetrica/php-ini-injection-probe` - PHP wrapper and ini directive
  injection probes
- `danielpetrica/php2shell-user-agent` - the `php2shell-<digits>` user-agent
  used by the commodity kits over this technique

Default remediation is `ban`: these signatures only ever occur in attack
traffic, and the underlying technique (attacker-controlled content written into
a session file, then included) is a direct LFI-to-RCE path.

Because the detection is in-band, the request is blocked *before* it reaches
the application - unlike the log-based scenario in this collection, which can
only alert after it has already been served.

## Use

```yaml
# section: acquis.d/appsec.yaml
source: appsec
listen_addr: 0.0.0.0:7422
appsec_configs:
  - danielpetrica/php-upload-progress
labels:
  type: appsec
```

With the Traefik bouncer plugin:

```yaml
crowdsecAppsecEnabled: true
crowdsecAppsecHost: crowdsec:7422
```

If you prefer a challenge-first profile, set `default_remediation: captcha`.
