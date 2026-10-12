import json

import pytest


@pytest.fixture
def detections():
    def document(record, event_id=1, data=None, timestamp="2026-10-12T04:00:00Z"):
        return {
            "kind": "evtx",
            "path": "fixture.evtx",
            "data": {
                "Event": {
                    "System": {
                        "EventID": event_id,
                        "EventRecordID": record,
                        "Computer": "LAB01",
                        "Channel": "Microsoft-Windows-Sysmon/Operational",
                        "Provider_attributes": {"Name": "Microsoft-Windows-Sysmon"},
                        "TimeCreated_attributes": {"SystemTime": timestamp},
                    },
                    "EventData": data
                    or {
                        "Image": r"C:\Windows\powershell.exe",
                        "ProcessId": "42",
                        "CommandLine": "powershell -NoProfile",
                        "User": "LAB\\analyst",
                    },
                }
            },
        }

    first = document(
        1,
        data={
            "Image": r"C:\Windows\powershell.exe",
            "ProcessId": "42",
            "CommandLine": "powershell -NoProfile",
            "DestinationIp": "192.0.2.10",
            "SHA256": "a" * 64,
            "QueryName": "example.test",
            "Url": "https://example.test/a'b",
        },
    )
    return [
        {
            "name": "PowerShell execution",
            "id": "rule-1",
            "level": "high",
            "tags": ["attack.execution", "attack.t1059.001"],
            "document": first,
        },
        {
            "name": "Second rule same event",
            "id": "rule-2",
            "level": "medium",
            "tags": ["attack.execution"],
            "document": first,
        },
        {
            "name": "Rare service installations",
            "id": "rule-3",
            "level": "low",
            "kind": "aggregate",
            "tags": ["attack.persistence", "attack.privilege_escalation", "attack.t1543.003"],
            "documents": [
                document(2, 7045, {"ServiceName": "Authorized Lab Service"}),
                document(3, 7045, {"ServiceName": "Another Lab Service"}),
            ],
        },
    ]


@pytest.fixture
def input_path(tmp_path, detections):
    path = tmp_path / "detections.json"
    path.write_text(json.dumps(detections))
    return path


@pytest.fixture
def document(input_path, tmp_path):
    from forensynth.cli import parser, run

    _, doc = run(
        parser().parse_args(
            [
                "--input",
                str(input_path),
                "--outdir",
                str(tmp_path / "reports"),
                "--environment",
                "simulation",
                "--authorized-test",
            ]
        )
    )
    return doc
