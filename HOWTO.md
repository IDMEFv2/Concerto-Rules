# HOWTO — write a detection or correlation rule

This guide explains how to add a parsing rule, how to write a correlation rule,
the pitfalls that make a rule fail **silently**, and the conventions to follow.
It is the companion of the rules published in this repository.


## 1. Rules reference (contributed)

All IDs below are unique across the whole installation and were added **without
removing** any existing rule. Parsing was validated end-to-end on the
docker-compose stack.

| Source | ID   | Log format detected                                   | IDMEFv2 Category | Priority |
|--------|------|-------------------------------------------------------|------------------|----------|
| ssh    | 1915 | `message repeated N times: [ Failed password ... ]`   | Access.Other     | Low/Med  |
| ssh    | 1916 | `Connection closed by ... [preauth]`                  | Recon.Network    | Low      |
| ssh    | 1917 | `reverse mapping ... POSSIBLE BREAK-IN ATTEMPT!`      | Recon.Network    | High     |
| ssh    | 1918 | `maximum authentication attempts exceeded for ...`    | Access.Other     | Medium   |
| sudo   | 2702 | `<user> : N incorrect password attempts ; ...`        | Access.Other     | Med/High |
| nginx  | 5644 | nginx `error.log` request error                       | Access.Unauthorized | Medium |

> **Not in this repository:** the shipped nginx rule **5643** only matches `GET`
> and hardcodes `Defense.Other`, which is not a V08 category. An enhancement
> (any HTTP method, all 4xx/5xx, category derived from the HTTP status) is
> proposed separately on Concerto-SIEM, since it modifies a shipped rule rather
> than adding one.

### Correlation rules

| Rule | Selects | Groups on | Threshold | Generated alert |
|------|---------|-----------|-----------|-----------------|
| `ssh_bruteforce.yml` | `Access.Other` + `Target_Service: sshd` | `Source_IP` | 10 / 5 min | `Access.Forced` / High |
| `nginx_scan.yml` | `Target_Service: nginx` | `Source_IP` | 15 / 1 min | `Recon.Network` / High |

Both group on **flat** fields, for the reason explained in section 3.

---

## 2. Writing a correlation rule

A **parsing** rule turns one raw log line into one IDMEFv2 alert. A
**correlation** rule works one level higher: it groups alerts that are already
stored and raises a new alert when a pattern emerges (for example, many failed
logins from the same source IP).

Correlation rules live in `correlator/rules/` and use the Sigma correlation
format. A rule has two YAML documents separated by `---`: first a **selection**
(which base alerts to look at), then the **correlation** itself.

Example — `correlator/rules/ssh_bruteforce.yml`:

```yaml
title: SSH failed login
name: ssh_failed_login
description: Failed SSH authentication events (sshd).
logsource:
    category: alerts
detection:
    selection:
        Category: Access.Other
        Target_Service: sshd
    condition: selection
---
title: SSH bruteforce (single source IP)
description: Many failed SSH logins coming from a single source IP.
idmefv2:
  Category:
    - "Access.Forced"
  Priority: "High"
correlation:
    type: event_count
    rules:
        - ssh_failed_login
    group-by:
        - Source_IP
    timespan: 5m
    condition:
        gte: 10
    generate: true
```

Field-by-field:

- **selection** — the fields an existing alert must have to be counted. Use the
  IDMEFv2 field names as stored. Use `Category` (a top-level field) plus a
  distinctive **flat** field such as `Target_Service` so the rule only matches the
  intended source. Never select on `Target.Service` or `Source.IP`: they live
  inside `nested` objects and match nothing (see section 3).
- **group-by** — the field the count is grouped on. It **must be a flat field**:
  `Source_IP` counts per attacking IP, `Target_User` per targeted account.
  Grouping on the nested `Source.IP` / `Target.User` never matches (section 3).
- **timespan** — the sliding window (e.g. `5m`, `1m`).
- **condition.gte** — the threshold that triggers the correlated alert.
- **idmefv2** — the Category/Priority of the **generated** alert.

For the generated alert to be usable, make sure the underlying parsing rules set
the fields you select and group on (here, ssh alerts must carry
`Category: Access.Other`, `Target_Service: sshd` and `Source_IP`).

---

## 3. Nested fields: why a `group-by` never matches
<a id="nested-fields"></a>

In the Elasticsearch mapping, `Source`, `Target`, `Sensor` and `Attachment` are
declared as **`nested`** objects. This has a consequence that is easy to miss:

> A **standard** `terms` aggregation on a field inside a nested object
> (e.g. `Target.User`, `Source.IP`) returns **no buckets**. The values are only
> visible through a **`nested`** aggregation.

Because a correlation `group-by` compiles down to a standard aggregation, a rule
grouped on `Source.IP` or `Target.User` finds nothing and never reaches its
threshold — **including the shipped `bruteforce.yml`**, which groups on
`Target.User`. The same applies to a *selection* on `Target.Service`.

The failure is **silent**: no error, no log entry, the correlator simply never
fires. That is why it can go unnoticed for a long time.

### Proven by A/B test (Kubernetes, fix #18 applied)

Two rules identical in every respect — same selection, same threshold, same
window — loaded in the same correlator, querying the same index at the same
instant. Only the grouping field differs:

| `group-by` | hits read / cycle | matches |
|------------|-------------------|---------|
| `Source.IP` (nested) | 7 | **0** |
| `Source_IP` (flat)   | 7 | **1** |

Identical hit counts prove both rules read the same documents: the selection and
the data access are not in question, only the `group-by` on a nested field fails.

> **Fix #18 does not fix this.** It repairs the GUI search (`Source(*)`)
> and the ingestion normalisation; it changes neither the index mapping (the four
> classes remain `nested`) nor the correlator. The test above was run with #18
> deployed.

### The fix: flatten what the correlation needs

A Ruby filter in `logstash/pipeline/00-my_stored.conf` copies the first entry of
each nested object into plain top-level keyword fields: `Source_IP`,
`Source_User`, `Target_User`, `Target_Service`. Rules then select and group on
those instead.

**Adding such a field requires three synchronised changes.** Miss one and the
field disappears without any error:

1. **the Ruby filter** — creates the field;
2. **the `prune` whitelist** in the same pipeline — otherwise Logstash drops it;
3. **`logstash/IDMEFv2.mapping`** — the mapping sets `dynamic: false`, so
   Elasticsearch silently ignores any undeclared field.

On an **existing** index the mapping file is not enough (it only applies at index
creation). Declare the field on the live index — a non-destructive operation:

```bash
curl -u elastic:elastic -H 'Content-Type: application/json' \
  -X PUT "http://localhost:9200/alerts/_mapping" \
  -d '{"properties":{"Target_Service":{"type":"keyword","norms":false}}}'
```

Measured on Kubernetes with fix #18 applied: `ssh_bruteforce` read 120
events → 1 correlated alert; `nginx_scan` read 48 → 1. Both alerts were stored
back with **0 schema rejection**, verified end to end up to the GUI.

## 4. Conventions (read before contributing a rule)

- **Use V08 categories.** `Category` must be a value of the `categoryEnum`
  in the deployed `IDMEFv2-light.schema` (128 values). The V08 bump removed
  several categories still used by shipped rules: `Attempt.Login`,
  `Recon.Scanning`, `Defense.Other`, `Login.Attempt` and
  `Intrusion.UserCompromise` no longer exist. Use `Access.Forced` for a
  brute-force outcome, `Recon.Network` for scanning, `Access.Unauthorized`
  for a denied access. **Do not copy a neighbouring rule to pick a
  category** — ssh 1905/1906, sudo 2701 and nginx 5643 still carry invalid
  ones. A rejected alert is tagged `_schemacheckfailure`, but the tag is
  removed by the `prune` filter before storage and the event is still sent
  to Kafka (see the `FIXIT` in `00-my_processed.conf`): nothing is visible
  in Elasticsearch. The only trace is the Logstash log:
  `docker logs proto-logstash-1 | grep _schemacheckfailure`.
- **Unique IDs.** Every rule `id` must be unique across the *entire*
  installation, not just within its file. Reusing an ID (even in another
  ruleset) breaks matching. Do not assume a range is free: for example ids
  `4001` and `4002` are already used by the `selinux` ruleset. Always grep the
  repository before choosing one: `grep -rn "id: <N>" logstash/rulesets/`. The
  rules in this repository use the free ids `1915`–`1918` (ssh), `2702` (sudo)
  and `5644` (nginx).
- **Do not overwrite.** Add your rules next to the existing ones; never replace a
  file wholesale, or you delete rules other users rely on.
- **Field names.** Follow the existing ECS-like scheme; do not invent field
  trees. Common fields:
  - `[Attachment][RawLog][Content][source][address]` — source IP/host
  - `[Attachment][RawLog][Content][destination][user][name]` — target user
  - `[Attachment][RawLog][Content][target][user][name]` — acting user (sudo/su)
  - `[Attachment][RawLog][Content][process][name]` — program name (predicate)
  - `[Attachment][RawLog][Content][process][command_line]` — command
  - `[Attachment][RawLog][Content][event][count]` — a numeric counter
- **Two files per parsing rule.** The Grok rule goes in `logstash/rulesets/`,
  its IDMEFv2 mapping (same `id`) in `logstash/idmef/`.
- **Always add a `samples:` entry** with a real log line — it documents the rule
  and makes it testable.
- **Category coherence for correlation.** If a rule is meant to feed a
  correlation, it must carry the Category the correlation selects
  (e.g. `Access.Other` for the SSH brute-force chain).

### Testing a new rule locally

1. Copy the rule files into the running stack (`logstash/rulesets/`,
   `logstash/idmef/`) and restart Logstash.

   > The shipped `docker-compose.yml` mounts `logstash/rulesets` but **not**
   > `logstash/idmef`. Without that volume the Grok rule loads and the mapping is
   > silently ignored, so the alert comes out with no Category. Add it to the
   > `logstash` service:
   > `- ./logstash/idmef:/usr/share/logstash/config/idmef:ro,Z`

2. Send a sample line to the syslog input:
   `echo '<sample>' | nc -w2 localhost 6514`.
3. Check the resulting alert in Elasticsearch (or the GUI).
4. **Check the Logstash log for a schema rejection** — this is the step people
   skip, and the reason an invalid rule looks fine:
   `docker logs proto-logstash-1 | grep -c _schemacheckfailure`
   The count must not increase. A rejected alert is still stored and displayed,
   so Elasticsearch and the GUI will not tell you anything is wrong.
