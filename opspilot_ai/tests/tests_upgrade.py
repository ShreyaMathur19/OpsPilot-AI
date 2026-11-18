
import tempfile
import unittest
from pathlib import Path

from opspilot import store, events, memory
from opspilot.recovery import safe_execute


class FakeAgent:
    def start(self, objective):
        assert "EVT-" in objective
        return {
            "status": "completed",
            "run_id": "RUN-FAKE",
            "result": "Test investigation completed"
        }


class UpgradeTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original = store.DB_PATH

        store.DB_PATH = Path(self.tmp.name) / "test.db"

        store.init_db()
        events.ensure_tables()

    def tearDown(self):
        store.DB_PATH = self.original
        self.tmp.cleanup()

    def sample(self, event_id="EVT-TEST"):
        return {
            "event_id": event_id,
            "device_id": "DEV-104",
            "category": "malware",
            "severity": "critical",
            "description": "Suspicious executable detected"
        }

    def test_event_ingestion(self):
        result = events.ingest(self.sample())
        self.assertEqual(result["status"], "accepted")

    def test_duplicate_prevention(self):
        events.ingest(self.sample())

        result = events.ingest(self.sample())

        self.assertEqual(result["status"], "duplicate")

        records = store.query(
            "SELECT * FROM alerts WHERE id='EVT-TEST'"
        )
        self.assertEqual(len(records), 1)

    def test_unknown_device(self):
        payload = self.sample()
        payload["device_id"] = "DEV-UNKNOWN"

        with self.assertRaises(ValueError):
            events.ingest(payload)

    def test_invalid_severity(self):
        payload = self.sample()
        payload["severity"] = "extreme"

        with self.assertRaises(ValueError):
            events.ingest(payload)

    def test_worker_execution(self):
        events.ingest(self.sample("EVT-WORKER"))

        result = events.process_one(
            agent_factory=FakeAgent
        )

        self.assertEqual(result["state"], "completed")

    def test_safe_retry(self):
        calls = []

        def flaky(name, args):
            calls.append(name)

            if len(calls) == 1:
                raise TimeoutError("Temporary failure")

            return {"status": "ok"}

        result = safe_execute(
            "get_device",
            {"device_id": "DEV-104"},
            executor=flaky,
            sleep=lambda s: None
        )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(calls), 2)

    def test_mutation_not_retried(self):
        calls = []

        def failing(name, args):
            calls.append(name)
            raise TimeoutError("Temporary failure")

        result = safe_execute(
            "create_incident",
            {},
            executor=failing,
            sleep=lambda s: None
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(result["attempts"], 1)

    def test_empty_memory(self):
        result = memory.similar_cases(
            "unknown historical incident"
        )

        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
