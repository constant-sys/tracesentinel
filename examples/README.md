# Reproducible demo / 可复现演示

`auth-demo.jsonl` is entirely synthetic. It uses documentation-only IP addresses and fictional users/hosts. It contains 14 events; no live systems were contacted.

With a 300-second window and threshold 5, expect exactly these **three alerts**, which do not represent three independent incidents:

| Rule | Evidence input lines | Explanation |
|---|---|---|
| TS-AUTH-001 | 2–6 | Five failures against `admin` on `lab-web` |
| TS-AUTH-003 | 2–7 | The same failures followed by a successful login |
| TS-AUTH-002 | 8–12 | Five different accounts failing from one source on `lab-vpn` |

Line 1 is a normal login. Lines 13–14 represent a mistyped password followed by success and should not alert. The demo proves these defined cases only; it does not measure accuracy on production traffic.

From the repository root:

```sh
python -m tracesentinel analyze examples/auth-demo.jsonl --output output/demo
```

Open `output/demo/report.html` locally. `report.json` contains source hash, rule parameters, counts and original evidence line references. The tracked `report.html` and `report.json` in this folder are generated from this synthetic fixture with the default configuration.

## OpenSSH fixture

`ssh-demo.txt` uses the common RFC 3164 `sshd` format. It is synthetic and uses documentation-only IPs. Run:

```sh
python -m tracesentinel analyze examples/ssh-demo.txt --format openssh --year 2026 --output output/ssh-demo
```

The six lines produce two findings: repeated failures and a success after those failures. The adapter preserves the original line numbers and skips unrelated `auth.log` noise. A real archived log must be interpreted with its collector timezone; the CLI currently uses UTC.
