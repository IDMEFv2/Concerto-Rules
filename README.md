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

## Corrections to shipped mappings — for review

**These three files are the exception to the "additions only" rule above.** They
*replace* mappings shipped by Concerto-SIEM, because those target the 2021
taxonomy rather than draft-08. They are staged here for review with the
maintainers before being carried over to Concerto-SIEM.

| File | Rules | Ids | What was wrong |
|---|---|---|---|
| `logstash/idmef/ssh.yml` | 10 | 1902–1914 | `[Analyzer][Type]` off-schema, `Analyzer.Data: Auth` off-enum, `Recon.Scanning` and `Intrusion.UserCompromise`/`Login.Attempt` no longer exist in draft-08 |
| `logstash/idmef/sudo.yml` | 2 | 2700–2701 | `[Severity]` off-schema, missing `Category` on 2700, `Defense.Other` on 2701 |
| `logstash/idmef/nginx.yml` | 1 | 5643 | `Defense.Other` hardcoded; now a translate on the HTTP status (403 → `Access.Unauthorized`, 404 → `Recon.Network`, 500 → `Availability.Failure`) |

28 non-conformities in total. The rule ids are unchanged, so nothing else has to
move. They do not collide with `ssh-auth-failures` (1915–1918), `ssh-recon`
(1916–1917), `sudo-auth-failures` (2702) or `nginx-error-log` (5644), which stay
as they are.

## IDMEFv2 mappings for shipped rulesets

Concerto-SIEM ships 75 parsing rulesets but only 3 IDMEFv2 mappings (ssh, sudo,
nginx): about 94% of the parsed rules produce no IDMEFv2 alert at all. The files
below supply the missing mapping for 14 security-relevant sources — 103 rules.

They add **no parsing rule**. Each one maps rules already shipped in
`Concerto-SIEM/logstash/rulesets/`, paired by rule id (`scripts/rules.rb` keys its
lookup on `id`, not on the ruleset name). Consequently `logstash/idmef/` here holds
more files than `logstash/rulesets/` — that is expected, the parsing side already
exists upstream.

| Family | Ruleset | Rules | Ids | Main categories |
|---|---|---|---|---|
| Firewall | `cisco-asa` | 34 | 195–507 | `Access.Unauthorized`, `Other.Undetermined`, `Access.Authorized` |
| Firewall | `juniper-srx` | 8 | 22001–22008 | `Access.Authorized`, `Other.Undetermined`, `Access.Unauthorized` |
| Firewall | `checkpoint` | 6 | 100–127 | `Other.Undetermined`, `Access.Unauthorized`, `Access.Authorized` |
| Firewall | `paloalto` | 6 | 24601–24606 | `Access.Authorized`, `Other.Undetermined`, `Access.Unauthorized` |
| Firewall | `sonicwall` | 6 | 4600–4605 | `Other.Undetermined`, `Access.Other`, `Fraud.Masquerade` |
| IDS/IPS | `cisco-ips` | 6 | 5001–5006 | `Other.Undetermined`, `Availability.HeartBeat` |
| IDS/IPS | `intrushield` | 4 | 24901–24904 | `Availability.Failure`, `Availability.Outage`, `Availability.HeartBeat` |
| VPN | `cisco-vpn` | 5 | 300–304 | `Access.Authorized`, `Access.Unauthorized` |
| AAA / identity | `tacas_net` | 9 | 120001–120009 | `Access.Authorized`, `Access.Unauthorized` |
| AAA / identity | `radius` | 5 | 35000–35004 | `Access.Unauthorized`, `Access.Authorized`, `Availability.HeartBeat` |
| AAA / identity | `ras-securid` | 4 | 24801–24804 | `Access.Unauthorized`, `Access.Forced`, `Access.Lost` |
| Host / auth | `pam` | 3 | 1–3 | `Access.Unauthorized`, `Access.Authorized` |
| Host / auth | `su` | 2 | 10000–10002 | `Access.Escalation`, `Access.Authorized` |
| Network / DDoS | `arbor` | 5 | 4300–4304 | `Availability.DDoS`, `Availability.Failure` |

### Conformance

All 103 mappings were checked against the draft-08 machine schema
(`IDMEFv2.schema`, Version 2.D.V08, 128 categories) with a conformance audit
tool. That tool is deliberately **not** part of this repository, which holds
rules only; it is kept with the contributor's working copy and can be provided on
request. On a deployment combining Concerto-SIEM and this repository:

```
79 parsed sources | 21 mapped | 480 parsing rules | 122 mapping rules
0 missing Category | 0 off-schema field | 0 off-enum value | 0 duplicate id
0 duplicate ruleset name | 0 orphan mapping
```

Ids were checked for collision against every ruleset shipped by Concerto-SIEM and
against the rules already in this repository: none.

**Status.** Conformance and id coverage are verified statically and reproducibly.
End-to-end validation (syslog injection to stored alert) has been performed for
ssh, sudo and nginx only; the 14 sources above are not yet injection-tested, and
8 of their parsing samples do not match their shipped pattern
(`cisco-asa` 195/196, `cisco-ips` 5001/5006, `cisco-vpn` 300, `pam` 1,
`radius` 35001, `sonicwall` 4600) — a pre-existing parsing issue, unchanged by
these mappings.

### Semantic review requested

Conformance is settled; the Category and Priority choices are not. 21 decision
points — generic IDS alerts mapped to `Other.Undetermined` for want of a captured
signature name, firewall denies as `Access.Unauthorized` vs `Recon.Network`,
whether success events should raise Info alerts at all — are submitted to the
consortium for arbitration.

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
