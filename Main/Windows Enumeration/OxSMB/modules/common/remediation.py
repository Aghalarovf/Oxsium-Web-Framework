import json
import os

from modules.common.attack_vector import SEVERITY_ORDER, evaluate_findings

MODULE_NAME = "remediation"

_DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "remediation.json")


def _load_dataset(path: str = _DATA_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


_DATASET = _load_dataset()
REMEDIATION_RULES = _DATASET.get("remediations", [])
REMEDIATION_RULES_BY_FINDING = {rule["finding_id"]: rule for rule in REMEDIATION_RULES}


def evaluate_remediations(module_results: list, matched_findings: list = None) -> list:
    if matched_findings is None:
        matched_findings = evaluate_findings(module_results)

    applicable = []
    for finding in matched_findings:
        rule = REMEDIATION_RULES_BY_FINDING.get(finding["id"])
        if rule is None:
            continue

        applicable.append(
            {
                "finding_id": finding["id"],
                "finding_title": finding["title"],
                "title": rule["title"],
                "priority": rule.get("priority", finding["severity"]),
                "recommendation": rule.get("recommendation", ""),
                "steps": rule.get("steps", []),
                "references": rule.get("references", []),
            }
        )

    applicable.sort(key=lambda entry: SEVERITY_ORDER.get(entry["priority"], 99))
    return applicable


def analyze(module_results: list) -> dict:
    findings = evaluate_findings(module_results)
    remediations = evaluate_remediations(module_results, matched_findings=findings)
    return {
        "findings": findings,
        "remediations": remediations,
    }
