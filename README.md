# Security Alert Correlation Agent

Three security tools — an identity provider, an EDR, a cloud audit log —
each raise alerts independently. None of them know about the other two.
A real incident often only becomes visible when you connect a login
anomaly, a suspicious process, and a privilege change into one story.

This project is a small working prototype of an agent that does that
correlation: given a time window, it queries all three log sources and
decides whether any of their events actually describe a single incident.

## Why this design

The interesting part isn't the demo data — it's the interface. The agent
never talks to "Entra ID" or "the EDR" directly. It talks to anything
implementing the `AlertSource` interface in [`sources/base.py`](sources/base.py):

```python
class AlertSource(ABC):
    def fetch_alerts(self, start_time, end_time) -> list[dict]: ...
    def get_field_mapping(self) -> dict: ...
```

The three sources in this repo (`sources/implementations.py`) are backed by
generated synthetic data, not a live tenant. But because they implement
this same interface, a real connector — Microsoft Graph sign-in logs,
Sentinel, CrowdStrike, whatever — could replace them without the agent's
reasoning logic changing at all. That's the actual architecture question a
production version of this would need to answer, and it's answered here on
day one rather than bolted on later.

## Two ways to run it

**`--mock`** — a rule-based fallback, no API key required. It groups events
that share an identity across at least two sources in the window.

**Default** — an LLM (Claude, via tool-calling) decides which sources to
query and reasons about *why* events are or aren't connected, rather than
just matching on shared identity. Requires `ANTHROPIC_API_KEY`.

```bash
pip install -r requirements.txt
python synthetic_data/generate_logs.py     # generates the three log files
python agent.py --mock                      # no API key needed
python agent.py                             # requires ANTHROPIC_API_KEY
```

## An honest finding from testing this

Running `--mock` surfaces something worth being upfront about: the
rule-based version over-correlates. It matched every event by user
`j.chandru` across the entire two-day window — including chrome.exe
opening and an unrelated Outlook session — not just the actual incident
chain (anomalous login → suspicious PowerShell → privilege change, all
within about 15 minutes).

That's not a bug I fixed by tuning the rule. It's the actual argument for
building this as an LLM-reasoning agent rather than a matching script:
"same identity, same day" is not the same claim as "same identity, tight
time window, escalating severity, plausible attack narrative." The mock
mode exists specifically to make that gap visible — a naive heuristic and
an agent that reasons about *why* events belong together are not the same
thing, and the difference is the whole point of the project.

## Ground truth for evaluation

`synthetic_data/generate_logs.py` embeds one deliberate incident chain
(user `j.chandru`: anomalous-location login → suspicious PowerShell
execution on their host → a Global Administrator role grant, all within
25 minutes) inside generated noise. That known answer is what makes it
possible to check whether the agent actually found the right thing,
rather than just producing plausible-looking output.

## What this is (and isn't)

A working prototype proving the correlation pattern on synthetic data with
an extensible source interface — not a production correlation engine. A
real version would need live connectors per platform, tuned time-window
and severity logic from real incident data, and a human-in-the-loop review
step before anything reached an actual SOC queue. This project answers "does
the core mechanism work and is the architecture right for it to grow,"
which is a different question from "is this ready to run against a real
tenant" — and it's honest about being the former.

## Roadmap

- [ ] Real Microsoft Graph identity connector (replacing the synthetic `IdentitySource`)
- [ ] Configurable time-window and severity-scoring logic
- [ ] A minimal web UI for reviewing flagged incidents

## Author

Jhanavi Kunthur Chandru — Master of Cyber Security, UNSW Bengaluru
