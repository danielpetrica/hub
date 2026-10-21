Ban source IPs whose request was blocked by the php2shell / PHP
upload-progress AppSec rules.

## Why this exists

AppSec in-band matches create a `waf` alert but do **not** emit pipeline
events by default, so a scenario cannot see them directly. What works is the
`crowdsecurity/appsec-logs` parser, which turns the AppSec datasource event
into `evt.Meta.log_type == "appsec-block"` with `evt.Meta.rule_name` set.
This trigger scenario then bans the source on the first blocked request.

Requires:

- `crowdsecurity/appsec-logs` parser installed
- `crowdsecurity/syslog-logs` + `crowdsecurity/dateparse-enrich` (CrowdSec does
  not feed AppSec events into the pipeline without them)
- a CrowdSec restart after installing the parser (a HUP reload is not enough
  for the appsec datasource)

The ban reaches the bouncer on the next decision-stream refresh (60s with the
Traefik plugin defaults); the offending request itself is blocked in-band
immediately.

## Scope

Only the rules of this collection are matched, so an alert from CRS or another
rule set stays a `waf` alert without an automatic ban.
