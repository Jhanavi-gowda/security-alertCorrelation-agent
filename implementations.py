"""
Concrete AlertSource implementations backed by the synthetic JSON logs.

Each one is deliberately thin — it just loads its file and maps fields.
A real connector (MicrosoftGraphIdentitySource, SentinelEndpointSource,
etc.) would replace fetch_alerts() with an actual API call, but would
implement this exact same interface, which is the point.
"""

import json
import os
from typing import List, Dict, Any
from .base import AlertSource

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "synthetic_data")


class IdentitySource(AlertSource):
    name = "identity"

    def fetch_alerts(self, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        with open(os.path.join(DATA_DIR, "identity_log.json")) as f:
            events = json.load(f)
        return [e for e in events if start_time <= e["timestamp"] <= end_time]

    def get_field_mapping(self) -> Dict[str, str]:
        return {"timestamp": "timestamp", "identity": "user", "ip": "ip", "detail": "event"}


class EndpointSource(AlertSource):
    name = "endpoint"

    def fetch_alerts(self, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        with open(os.path.join(DATA_DIR, "endpoint_log.json")) as f:
            events = json.load(f)
        return [e for e in events if start_time <= e["timestamp"] <= end_time]

    def get_field_mapping(self) -> Dict[str, str]:
        return {"timestamp": "timestamp", "identity": "user", "host": "host", "detail": "process"}


class CloudAuditSource(AlertSource):
    name = "cloud_audit"

    def fetch_alerts(self, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        with open(os.path.join(DATA_DIR, "cloud_audit_log.json")) as f:
            events = json.load(f)
        return [e for e in events if start_time <= e["timestamp"] <= end_time]

    def get_field_mapping(self) -> Dict[str, str]:
        return {"timestamp": "timestamp", "identity": "actor", "detail": "event"}
