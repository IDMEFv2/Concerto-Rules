# Concerto-Rules

Detection and correlation rules for Concerto SIEM, contributed on top of the
rulesets shipped with [Concerto-SIEM](https://github.com/IDMEFv2/Concerto-SIEM).

Rules here are **additions**: they never replace a shipped file. See
[HOWTO.md](HOWTO.md) to write your own.

## Layout

The tree mirrors Concerto-SIEM, so files can be copied straight into a deployment:

```
logstash/rulesets/    parsing rules (Grok)        -> config/rulesets/
logstash/idmef/       IDMEFv2 mapping (same id)   -> config/idmef/
correlator/rules/     Sigma correlation rules     -> /opt/elastalert/rules/
```

Both `rulesets/*.yml` and `idmef/*.yml` are loaded by glob, so a contributed file
is simply added to the ones already present.

## Install

```bash
cp logstash/rulesets/*.yml  <concerto>/logstash/rulesets/
cp logstash/idmef/*.yml     <concerto>/logstash/idmef/
docker compose -p proto restart logstash
```

> **The `idmef` directory is not mounted by the shipped `docker-compose.yml`.**
> Only `logstash/rulesets` is. Without the volume below, the Grok rules load but
> their IDMEFv2 mapping is silently ignored — the alert is produced with no
> Category and no Description. Add it to the `logstash` service:
>
> ```yaml
>       - ./logstash/idmef:/usr/share/logstash/config/idmef:ro,Z
> ```

## Rules provided

| File | Id | Detects | IDMEFv2 category |
|------|----|---------|------------------|
| `ssh-auth-failures` | 1915 | repeated failed password (syslog dedup) | Access.Other |
| `ssh-auth-failures` | 1918 | maximum authentication attempts exceeded | Access.Other |
| `ssh-recon` | 1916 | connection closed before authentication | Recon.Network |
| `ssh-recon` | 1917 | reverse-mapping mismatch, possible break-in | Recon.Network |
| `sudo-auth-failures` | 2702 | N incorrect sudo password attempts | Access.Other |
| `nginx-error-log` | 5644 | nginx error-log request error | Access.Unauthorized |

Files are named after what they detect, not after their author. A ruleset holds
rules that share a purpose and a category, so the file name tells a maintainer
what is inside.

| Correlation rule | Detects | Groups on | Threshold | Generates |
|------------------|---------|-----------|-----------|-----------|
| `ssh_bruteforce.yml` | many failed SSH logins from one IP | `Source_IP` | 10 / 5 min | Access.Forced |
| `nginx_scan.yml` | many HTTP errors from one IP | `Source_IP` | 15 / 1 min | Recon.Network |

All six parsing rules were validated end to end on the compose stack: a sample log
is injected on the syslog input, the resulting IDMEFv2 alert is checked in
Elasticsearch, and the Logstash log is checked for schema rejections.

The two correlation rules were validated on the Kubernetes deployment, in the
exact version published here: each reads its base alerts, reaches its threshold,
and its correlated alert is generated, re-ingested and stored — `Access.Forced`
for `ssh_bruteforce`, `Recon.Network` for `nginx_scan`, both with the source IP
carried over.

## Prerequisite for the correlation rules

The correlation rules group on `Source_IP`, a **flat** field. They will **not**
fire on a stock deployment, because `Source` is mapped as a `nested` object and a
Sigma `group-by` cannot express a nested path — the rule reads the events but
produces no match, silently.

The flattening (a Ruby filter in `00-my_stored.conf` plus the mapping) belongs to
the pipeline, not to this repository, and is proposed separately on Concerto-SIEM.
Until it is merged, use the rules with your own flattening. See
[HOWTO.md](HOWTO.md#nested-fields).

## Conventions

Read [HOWTO.md](HOWTO.md) before contributing. In short:

- **rule id unique across the whole installation** — grep before choosing;
- **ruleset name unique** — the Grok filter is keyed by name, a duplicate silently
  overrides another ruleset;
- **category taken from the V08 `categoryEnum`** — several shipped rules still use
  values that no longer exist, so do not copy a neighbour;
- **one `samples:` entry per rule**, with a real log line.
