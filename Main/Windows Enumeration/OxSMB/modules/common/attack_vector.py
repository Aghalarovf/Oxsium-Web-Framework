import json
import os

MODULE_NAME = "attack_vector"

_DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack_vector.json")

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _load_dataset(path: str = _DATA_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


_DATASET = _load_dataset()
FINDING_RULES = _DATASET.get("findings", [])
ATTACK_VECTOR_RULES = _DATASET.get("attack_vectors", [])
FINDING_RULES_BY_ID = {rule["id"]: rule for rule in FINDING_RULES}


def _index_modules_by_name(module_results: list) -> dict:
    indexed = {}
    for module_result in module_results or []:
        if module_result.get("status") != "ok":
            continue
        name = module_result.get("module")
        data = module_result.get("data") or {}
        if name:
            indexed[name] = data
    return indexed


def _condition_matches(data: dict, condition: dict) -> bool:
    field = condition.get("field")
    if field not in data:
        return False
    actual = data.get(field)

    if "equals" in condition:
        return actual == condition["equals"]
    if "not_equals" in condition:
        return actual != condition["not_equals"]
    if "in" in condition:
        return actual in condition["in"]
    if "truthy" in condition:
        return bool(actual) == bool(condition["truthy"])

    return False


def evaluate_findings(module_results: list) -> list:
    indexed = _index_modules_by_name(module_results)
    matched = []

    for rule in FINDING_RULES:
        module_name = rule.get("module")
        module_data = indexed.get(module_name)
        if module_data is None:
            continue

        condition = rule.get("when", {})
        if not _condition_matches(module_data, condition):
            continue

        matched.append(
            {
                "id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "module": module_name,
                "evidence_field": condition.get("field"),
                "evidence_value": module_data.get(condition.get("field")),
            }
        )

    matched.sort(key=lambda entry: SEVERITY_ORDER.get(entry["severity"], 99))
    return matched


def evaluate_attack_vectors(module_results: list, matched_findings: list = None) -> list:
    if matched_findings is None:
        matched_findings = evaluate_findings(module_results)

    matched_ids = {entry["id"] for entry in matched_findings}
    applicable = []

    for rule in ATTACK_VECTOR_RULES:
        required = set(rule.get("requires", []))
        if not required:
            continue
        if not required.issubset(matched_ids):
            continue

        applicable.append(
            {
                "id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "requires": sorted(required),
                "mitre_attack": rule.get("mitre_attack", {}),
                "summary": rule.get("summary", ""),
                "narrative": rule.get("narrative", []),
                "impact": rule.get("impact", ""),
                "references": rule.get("references", []),
            }
        )

    applicable.sort(key=lambda entry: SEVERITY_ORDER.get(entry["severity"], 99))
    return applicable


def analyze(module_results: list) -> dict:
    findings = evaluate_findings(module_results)
    attack_vectors = evaluate_attack_vectors(module_results, matched_findings=findings)
    return {
        "findings": findings,
        "attack_vectors": attack_vectors,
    }
