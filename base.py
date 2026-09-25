"""
AlertSource — the interface every log source implements.

This is the key design decision in the project: the agent never talks
to "Entra ID" or "the EDR" directly. It talks to anything implementing
this interface. That means a real Sentinel or Splunk connector can be
dropped in later without touching the agent's reasoning logic at all —
it just has to implement fetch_alerts() and get_field_mapping().

The three sources in synthetic_data/ are the reference implementation
against this interface, using generated data instead of a live API.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any


class AlertSource(ABC):
    """Contract for any log/alert source the correlation agent can query."""

    name: str  # e.g. "identity", "endpoint", "cloud_audit"

    @abstractmethod
    def fetch_alerts(self, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        """
        Return raw alert/event records in [start_time, end_time],
        as a list of dicts. Each dict's shape is source-specific —
        that's what get_field_mapping() is for.
        """
        raise NotImplementedError

    @abstractmethod
    def get_field_mapping(self) -> Dict[str, str]:
        """
        Map this source's field names onto the agent's common vocabulary:
        {'timestamp': <field>, 'identity': <field>, 'ip': <field>, 'severity': <field>}

        This is what lets the agent reason across sources with wildly
        different native schemas without hardcoding per-source logic.
        """
        raise NotImplementedError
