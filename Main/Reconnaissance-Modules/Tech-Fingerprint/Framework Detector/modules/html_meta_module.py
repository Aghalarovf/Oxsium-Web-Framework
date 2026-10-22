import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Tuple

from core.models import DetectionMatch, Transaction
from modules.base import BaseDetector


class MetaTagParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta_tags: List[Dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Any]]) -> None:
        if tag.lower() != "meta":
            return
        attr_dict = {key.lower(): (value or "") for key, value in attrs}
        self.meta_tags.append(attr_dict)


class HtmlMetaDetector(BaseDetector):
    name = "html_meta"
    rule_key = "html"

    def prepare(self, transaction: Transaction) -> None:
        if transaction.body and transaction.meta_tags is None:
            transaction.meta_tags = self._extract_meta_tags(transaction.body)

    def detect(self, transaction: Transaction, signatures: Dict[str, Dict[str, Any]]) -> List[DetectionMatch]:
        matches: List[DetectionMatch] = []
        if not transaction.body:
            return matches

        meta_tags = transaction.meta_tags
        if meta_tags is None:
            meta_tags = self._extract_meta_tags(transaction.body)

        for framework, category, rule in self.iter_rules(signatures):
            rule_type = rule.get("type", "body")
            confidence = int(rule.get("confidence", 40))
            pattern = rule.get("pattern")
            if not pattern:
                continue

            if rule_type == "meta":
                meta_name = str(rule.get("name", "")).strip().lower()
                evidence = self._match_meta(meta_tags, meta_name, pattern)
            elif rule_type == "body":
                evidence = self._match_body(transaction.body, pattern)
            else:
                evidence = None

            if evidence is None:
                continue

            matches.append(
                DetectionMatch(
                    framework=framework,
                    category=category,
                    confidence=confidence,
                    module=self.name,
                    evidence=evidence,
                    transaction_url=transaction.url,
                    transaction_source=transaction.source,
                )
            )

        return matches

    @staticmethod
    def _extract_meta_tags(body: str) -> List[Dict[str, str]]:
        parser = MetaTagParser()
        try:
            parser.feed(body)
        except Exception:
            return []
        return parser.meta_tags

    @staticmethod
    def _match_meta(meta_tags: List[Dict[str, str]], meta_name: str, pattern: str):
        for tag in meta_tags:
            tag_name = tag.get("name", "").strip().lower()
            if meta_name and tag_name != meta_name:
                continue
            content = tag.get("content", "")
            if re.search(pattern, content, re.IGNORECASE):
                return f"meta[name={tag_name or 'unknown'}]: {content.strip()}"
        return None

    @staticmethod
    def _match_body(body: str, pattern: str):
        found = re.search(pattern, body, re.IGNORECASE)
        if not found:
            return None
        snippet = found.group(0)
        if len(snippet) > 80:
            snippet = snippet[:80] + "..."
        return f"body pattern matched: {snippet}"
