# Detection rules / 检测规则

Rules identify patterns for investigation, not confirmed attacks. Defaults: 300 seconds, 5 failures or distinct accounts. CLI `--threshold` sets all three thresholds; Python `EngineConfig` supports separate values.

## TS-AUTH-001: repeated failures

Group: source IP + host + username. Alert on ≥5 failures in the inclusive time window. Context: [MITRE ATT&CK T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/). This is an analytical mapping, not certification or exhaustive ATT&CK coverage.

False positives: forgotten password, expired service-account credentials, scripted retry. False negatives: distributed sources or low-volume guessing. Investigate source ownership, normal account behavior, retry interval and subsequent session activity.

## TS-AUTH-002: multi-account failure burst

Group: source IP + host. Alert on ≥5 distinct failed usernames in the window. Context: [MITRE ATT&CK T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/). Password values are absent, so this detector cannot establish that a single password was reused. It may also detect broad guessing or credential stuffing.

False positives: shared NAT, identity-provider outage, test automation. False negatives: low-and-slow spraying, distributed sources, spread across hosts. Validate identity-provider and MFA outcomes before classifying the behavior.

## TS-AUTH-003: success after repeated failures

Group: source IP + host + username. Correlate a success with ≥5 preceding failures inside its window. A success sharing a timestamp with failures considers only earlier source lines. Suppress repeated successes against an unchanged last failure.

This raises investigation priority; it does not prove credential theft. A legitimate user remembering a password can generate exactly this sequence. Examine subsequent actions and independent endpoint/session telemetry. No separate ATT&CK claim is made for this heuristic alone.

## Suppression and evidence

Burst rules emit on threshold crossing and re-arm after the active window falls below threshold. The report captures the triggering window. It does not merge different rules into one incident, nor update a previously emitted finding with later evidence. Rules are batch-local; separate runs do not share state.

## Validation

Each rule needs a positive fixture, a negative fixture, exact-window boundary tests, host-isolation tests and an explanation of expected errors. The repository demo gives 3 expected findings from 14 fully synthetic events. The v0.3 [evaluation suite](evaluation.md) adds 12 labeled synthetic scenarios, including known false positives and misses. It scores scenario-rule pairs, not incident attribution or evidence accuracy. Precision/recall on representative independent labeled data remains future work.
