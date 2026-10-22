# TraceSentinel · Detection evaluation

Dataset: **auth&#45;synthetic&#45;v1** · tool version 0&#46;3&#46;1

Authored synthetic attack and benign scenarios&#46; Labels describe scenario intent&#44; not detector output&#46; This is a regression suite&#44; not a production accuracy estimate&#46;

**Synthetic regression scenarios. These results do not estimate production accuracy.**

12 scenarios · 64 events · 36 scenario-rule pairs · 11 raw alerts

Input SHA-256: `cc30f0eef271101777b0f831aed8eb7f36a7858f03707278d3f404d82ab1cfef`

## Measurement

Each scenario runs independently. For each of the three rules, at least one alert means a positive prediction. Repeated alerts count once per scenario-rule pair. Labels express authored scenario intent and are independent of the configured threshold. All raw alerts and their event indices remain in evaluation.json.

A matching rule anywhere in a scenario counts as a hit; identity, timing and evidence accuracy are not scored here. N/A means a zero denominator. Overall metrics sum the counts from all rules before dividing (micro aggregation).

| Rule | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Overall | 6 | 4 | 2 | 24 | 60.0% | 75.0% | 66.7% |
| TS-AUTH-001 | 4 | 2 | 1 | 5 | 66.7% | 80.0% | 72.7% |
| TS-AUTH-002 | 1 | 1 | 1 | 9 | 50.0% | 50.0% | 50.0% |
| TS-AUTH-003 | 1 | 1 | 0 | 10 | 50.0% | 100.0% | 66.7% |

## Configuration

| Parameter | Value |
|---|---:|
| brute&#95;force&#95;threshold | 5 |
| password&#95;spray&#95;threshold | 5 |
| success&#95;after&#95;failures&#95;threshold | 5 |
| window&#95;seconds | 300 |

## Scenario results

| Scenario | Expected rules | Predicted rules | False positives | False negatives |
|---|---|---|---|---|
| benign&#45;login | — | — | — | — |
| benign&#45;password&#45;recovery | — | TS-AUTH-001, TS-AUTH-003 | TS-AUTH-001, TS-AUTH-003 | — |
| benign&#45;service&#45;retry | — | TS-AUTH-001 | TS-AUTH-001 | — |
| benign&#45;shared&#45;nat | — | TS-AUTH-002 | TS-AUTH-002 | — |
| benign&#45;typos | — | — | — | — |
| distributed&#45;spray | TS-AUTH-002 | — | — | TS-AUTH-002 |
| exact&#45;window&#45;guessing | TS-AUTH-001 | TS-AUTH-001 | — | — |
| guessing&#45;then&#45;success | TS-AUTH-001, TS-AUTH-003 | TS-AUTH-001, TS-AUTH-003 | — | — |
| password&#45;guessing | TS-AUTH-001 | TS-AUTH-001 | — | — |
| password&#45;spray | TS-AUTH-002 | TS-AUTH-002 | — | — |
| slow&#45;guessing | TS-AUTH-001 | — | — | TS-AUTH-001 |
| two&#45;guessing&#45;bursts | TS-AUTH-001 | TS-AUTH-001 | — | — |

## Scenario intent

- **benign&#45;login**: Routine legitimate login&#59; no suspicious sequence&#46;
- **benign&#45;password&#45;recovery**: Legitimate user remembers the password after five errors&#46; Failure and success telemetry resembles compromise&#46;
- **benign&#45;service&#45;retry**: Legitimate service retries a stale password five times&#59; expected no malicious activity&#44; but burst rule will flag it&#46;
- **benign&#45;shared&#45;nat**: Five legitimate users behind one NAT each mistype once&#46; Shared egress resembles spraying&#46;
- **benign&#45;typos**: Legitimate user mistypes twice and then succeeds&#46;
- **distributed&#45;spray**: Coordinated simulated spray uses five source IPs and five accounts&#59; per&#45;source grouping misses the campaign&#46;
- **exact&#45;window&#45;guessing**: Simulated guessing has exactly five failures in an inclusive 300&#45;second window&#46;
- **guessing&#45;then&#45;success**: Simulated attacker guesses a password and authenticates after five failures&#46;
- **password&#45;guessing**: Simulated attacker guesses one account&#39;s password six times in a short burst&#46;
- **password&#45;spray**: Simulated attacker tries a common password against six accounts&#46; Password reuse is scenario knowledge&#44; absent from telemetry&#46;
- **slow&#45;guessing**: Simulated attacker guesses six times at two&#45;minute intervals&#46; The default short window misses this behavior&#46;
- **two&#45;guessing&#45;bursts**: Two simulated guessing bursts for one account&#44; separated by ten minutes&#46; Two raw alerts count as one positive scenario&#45;rule pair&#46;

## Limits

This hand-authored corpus is small, intentionally includes known failure cases, and is neither a representative sample nor a held-out test set. Its benign/malicious labels include contextual knowledge unavailable to the detector. Do not tune and claim general accuracy on the same cases. It evaluates normalized-event rule behavior; OpenSSH parsing, ingestion loss, incident matching and production false-positive rates require separate evaluation.
