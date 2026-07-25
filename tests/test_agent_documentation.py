import json
from pathlib import Path
import unittest

from scripts.vibesec.agents import ADAPTER_IDS, CONTRACT_ID, TASK_IDS, load_catalog

ROOT = Path(__file__).resolve().parents[1]


class AgentDocumentationTests(unittest.TestCase):
    def test_machine_objects_and_human_docs_link_both_directions(self):
        catalog = load_catalog(ROOT)
        mapping = json.loads((ROOT / "machine/agents/documentation-map.json").read_text(encoding="utf-8"))
        contract_doc = (ROOT / catalog["contract"]["human_documentation"]).read_text(encoding="utf-8")
        self.assertIn(CONTRACT_ID, contract_doc)
        for adapter_id in ADAPTER_IDS:
            adapter = catalog["adapters"][adapter_id]
            doc = (ROOT / adapter["human_documentation"]).read_text(encoding="utf-8")
            self.assertIn(adapter["object_id"], doc)
            self.assertEqual(mapping["objects"][adapter["object_id"]], adapter["human_documentation"])
        task_doc = (ROOT / "docs/agent-task-pack.md").read_text(encoding="utf-8")
        for task_id in TASK_IDS:
            self.assertIn(f"`{task_id}`", task_doc)

    def test_public_agent_docs_cover_lifecycle_and_threat_boundaries(self):
        combined = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in (
                "docs/multi-agent-support.md", "docs/agent-contract.md", "docs/agent-adapters.md",
                "docs/agent-task-pack.md", "docs/agent-safety-model.md", "docs/agent-installation.md",
                "docs/agent-upgrades.md",
            )
        ).casefold()
        for marker in (
            "dry run", "--write", "never overwritten", "prompt injection", "credentials",
            "external agent cli", "disabled", "digest", "capability", "human authorization",
        ):
            self.assertIn(marker, combined)

    def test_official_conventions_have_primary_links_and_review_date(self):
        catalog = load_catalog(ROOT)
        expected_hosts = {
            "codex": "learn.chatgpt.com",
            "claude-code": "code.claude.com",
            "gemini-cli": "google-gemini.github.io",
            "kimi-cli": "moonshotai.github.io",
        }
        for adapter_id, adapter in catalog["adapters"].items():
            self.assertIn(expected_hosts[adapter_id], adapter["official_documentation"])
            self.assertEqual(adapter["verified_on"], "2026-07-24")


if __name__ == "__main__":
    unittest.main()
