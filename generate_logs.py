"""
Generates synthetic logs across three sources with a KNOWN ground truth:
some events are deliberately correlated (same identity, overlapping time
window, escalating severity) and most are unrelated noise.

This ground truth is what lets you actually evaluate the agent — you know
which alerts SHOULD be grouped, so you can check whether it found them.
"""

import json
import random
from datetime import datetime, timedelta

random.seed(42)  # reproducible runs

USERS = ["j.chandru", "r.singh", "a.mehta", "s.rao", "svc-backup-01", "p.iyer"]
HOSTS = ["WKS-4471", "WKS-5502", "SRV-DB01", "WKS-3390"]
IPS_NORMAL = ["49.204.1.12", "103.21.55.3"]
IPS_SUSPICIOUS = ["185.220.101.7"]  # simulated known-bad range

BASE_TIME = datetime(2026, 9, 26, 9, 0, 0)


def ts(offset_minutes: int) -> str:
    return (BASE_TIME + timedelta(minutes=offset_minutes)).isoformat()


def generate_incident_chain():
    """One deliberately correlated incident: impossible-travel login ->
    suspicious process on the same user's host -> a role change by that user."""
    user = "j.chandru"
    ip = IPS_SUSPICIOUS[0]
    host = "WKS-4471"

    identity_events = [
        {"timestamp": ts(0), "user": user, "ip": IPS_NORMAL[0], "event": "sign_in_success", "location": "Bengaluru, IN"},
        {"timestamp": ts(12), "user": user, "ip": ip, "event": "sign_in_success", "location": "Bucharest, RO"},
    ]
    endpoint_events = [
        {"timestamp": ts(18), "host": host, "user": user, "event": "process_created", "process": "powershell.exe -enc <base64>"},
    ]
    cloud_events = [
        {"timestamp": ts(25), "actor": user, "event": "role_assignment_created", "role": "Global Administrator", "target": user},
    ]
    return identity_events, endpoint_events, cloud_events


def generate_noise(n_identity=25, n_endpoint=20, n_cloud=15):
    identity, endpoint, cloud = [], [], []
    for _ in range(n_identity):
        identity.append({
            "timestamp": ts(random.randint(-500, 500)),
            "user": random.choice(USERS),
            "ip": random.choice(IPS_NORMAL),
            "event": "sign_in_success",
            "location": "Bengaluru, IN",
        })
    for _ in range(n_endpoint):
        endpoint.append({
            "timestamp": ts(random.randint(-500, 500)),
            "host": random.choice(HOSTS),
            "user": random.choice(USERS),
            "event": "process_created",
            "process": random.choice(["chrome.exe", "outlook.exe", "code.exe", "explorer.exe"]),
        })
    for _ in range(n_cloud):
        cloud.append({
            "timestamp": ts(random.randint(-500, 500)),
            "actor": random.choice(USERS),
            "event": random.choice(["resource_created", "storage_account_key_regenerated", "nsg_rule_modified"]),
            "role": None,
            "target": None,
        })
    return identity, endpoint, cloud


def main():
    inc_id, inc_ep, inc_cl = generate_incident_chain()
    noise_id, noise_ep, noise_cl = generate_noise()

    identity_log = sorted(inc_id + noise_id, key=lambda e: e["timestamp"])
    endpoint_log = sorted(inc_ep + noise_ep, key=lambda e: e["timestamp"])
    cloud_log = sorted(inc_cl + noise_cl, key=lambda e: e["timestamp"])

    with open("synthetic_data/identity_log.json", "w") as f:
        json.dump(identity_log, f, indent=2)
    with open("synthetic_data/endpoint_log.json", "w") as f:
        json.dump(endpoint_log, f, indent=2)
    with open("synthetic_data/cloud_audit_log.json", "w") as f:
        json.dump(cloud_log, f, indent=2)

    print(f"Generated {len(identity_log)} identity events, "
          f"{len(endpoint_log)} endpoint events, "
          f"{len(cloud_log)} cloud audit events.")
    print("Ground truth: one correlated incident chain involving user "
          "'j.chandru' across all three sources, embedded among the noise.")


if __name__ == "__main__":
    main()
