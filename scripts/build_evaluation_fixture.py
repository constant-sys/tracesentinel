"""Build authored synthetic scenarios; no detector is used to assign labels."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path


START = datetime(2026, 9, 1, tzinfo=timezone.utc)


def event(second, *, username="alice", ip="192.0.2.10", success=False):
    return {
        "timestamp": (START + timedelta(seconds=second)).isoformat().replace("+00:00", "Z"),
        "event_type": "auth_success" if success else "auth_failure",
        "source_ip": ip, "username": username, "host": "synthetic-ssh",
    }


def scenario(id, description, expected_rules, events):
    return dict(id=id, description=description, expected_rules=expected_rules, events=events)


def build_dataset():
    brute, spray, success = "TS-AUTH-001", "TS-AUTH-002", "TS-AUTH-003"
    return {
        "schema_version": 1,
        "dataset_id": "auth-synthetic-v1",
        "synthetic": True,
        "description": "Authored synthetic attack and benign scenarios. Labels describe scenario intent, not detector output. This is a regression suite, not a production accuracy estimate.",
        "scenarios": [
            scenario("benign-login", "Routine legitimate login; no suspicious sequence.", [], [event(0, success=True)]),
            scenario("benign-typos", "Legitimate user mistypes twice and then succeeds.", [],
                     [event(0), event(10), event(20, success=True)]),
            scenario("password-guessing", "Simulated attacker guesses one account's password six times in a short burst.", [brute],
                     [event(i) for i in range(6)]),
            scenario("password-spray", "Simulated attacker tries a common password against six accounts. Password reuse is scenario knowledge, absent from telemetry.", [spray],
                     [event(i, username=f"user-{i}") for i in range(6)]),
            scenario("guessing-then-success", "Simulated attacker guesses a password and authenticates after five failures.", [brute, success],
                     [event(i) for i in range(5)] + [event(5, success=True)]),
            scenario("slow-guessing", "Simulated attacker guesses six times at two-minute intervals. The default short window misses this behavior.", [brute],
                     [event(i * 120) for i in range(6)]),
            scenario("distributed-spray", "Coordinated simulated spray uses five source IPs and five accounts; per-source grouping misses the campaign.", [spray],
                     [event(i, username=f"user-{i}", ip=f"198.51.100.{i+1}") for i in range(5)]),
            scenario("benign-service-retry", "Legitimate service retries a stale password five times; expected no malicious activity, but burst rule will flag it.", [],
                     [event(i, username="backup-service") for i in range(5)]),
            scenario("benign-shared-nat", "Five legitimate users behind one NAT each mistype once. Shared egress resembles spraying.", [],
                     [event(i, username=f"staff-{i}") for i in range(5)]),
            scenario("benign-password-recovery", "Legitimate user remembers the password after five errors. Failure and success telemetry resembles compromise.", [],
                     [event(i) for i in range(5)] + [event(5, success=True)]),
            scenario("exact-window-guessing", "Simulated guessing has exactly five failures in an inclusive 300-second window.", [brute],
                     [event(i * 75) for i in range(5)]),
            scenario("two-guessing-bursts", "Two simulated guessing bursts for one account, separated by ten minutes. Two raw alerts count as one positive scenario-rule pair.", [brute],
                     [event(i) for i in range(5)] + [event(600 + i) for i in range(5)]),
        ],
    }


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "examples" / "evaluation" / "auth-synthetic-v1.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_dataset(), ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8", newline="\n")
    print(f"Wrote {target.name}: 12 authored synthetic scenarios.")
