# Synthetic authentication evaluation

`auth-synthetic-v1.json` contains 12 authored scenarios and 64 events. All IPs and identities are fictional/documentation examples. It includes benign activity, malicious intent, predictable false positives and known misses. Labels are written independently of the detector's output.

Run from the repository root:

```sh
python -m tracesentinel evaluate examples/evaluation/auth-synthetic-v1.json --output output/evaluation
```

Default counts across 36 scenario-rule pairs: **TP 6, FP 4, FN 2, TN 24**. A count is a scenario-rule decision, not an individual alert or incident. Repeated alerts in a scenario count once for that rule. Full interpretation and alternative configurations: [evaluation methodology](../../docs/evaluation.md).

| Scenario | Why it exists |
|---|---|
| benign-login | Ordinary successful login |
| benign-typos | A few mistakes followed by success |
| password-guessing | Fast single-account malicious guessing |
| password-spray | Malicious attempts across accounts |
| guessing-then-success | Simulated compromise sequence |
| slow-guessing | Known short-window miss |
| distributed-spray | Known per-source grouping miss |
| benign-service-retry | Stale service password causes false positive |
| benign-shared-nat | Shared egress resembles spray |
| benign-password-recovery | Legitimate recovery resembles compromise |
| exact-window-guessing | Inclusive 300-second boundary |
| two-guessing-bursts | Raw alert count differs from metric sample count |

The generator is `scripts/build_evaluation_fixture.py`; rebuilding should produce identical bytes. The generated [evaluation.md](evaluation.md) and [evaluation.json](evaluation.json) are checked-in reference outputs for default configuration. They measure this synthetic corpus only, not production accuracy.
