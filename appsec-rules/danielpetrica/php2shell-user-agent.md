AppSec rule for the `php2shell` commodity exploitation kit.

Observed in access logs while this rule was being written, on requests whose
`User-Agent` header contains a per-connection counter:

```text
User-Agent: php2shell-109619
Content-Type: multipart/form-data; boundary=B7kQpoc619

User-Agent: php2shell-109618
Content-Type: multipart/form-data; boundary=B7kQpoc618
```

The User-Agent is paired with a multipart body - the same shape as the PHP
`session.upload_progress` abuse covered by the
`danielpetrica/php-upload-progress` rule - so the UA alone is treated as
exploitation tooling rather than a scan.

The header value is trivially spoofable, which is why this rule is not relied
upon alone; paired with the `php2shell` log scenario it gives early-warning
visibility even on setups where AppSec is not deployed.

This rule requires the `crowdsecurity/base-config` appsec rule (it ships with an
`appsec-config`), or any appsec config that implements it.
