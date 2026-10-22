import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Tuple

from core.models import DetectionMatch, Transaction
from modules.base import BaseDetector

JS_URL_RE = re.compile(r"\.m?js(?:$|[?#])", re.IGNORECASE)


class ResourceParser(HTMLParser):
    """Collects <script src> and <link href> URLs from an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Any]]) -> None:
        tag = tag.lower()
        attr_dict = {key.lower(): (value or "") for key, value in attrs}
        if tag == "script" and attr_dict.get("src"):
            self.urls.append(attr_dict["src"])
        elif tag == "link" and attr_dict.get("href"):
            self.urls.append(attr_dict["href"])


class ScriptsDetector(BaseDetector):
    """Evaluates `html` rules of type "script" against script/stylesheet URLs.

    Sources: <script src>/<link href> found in HTML bodies, plus the URL of the
    transaction itself when it is a JavaScript resource.
    """

    name = "scripts"
    rule_key = "html"

    def prepare(self, transaction: Transaction) -> None:
        if transaction.script_urls is not None:
            return
        urls: List[str] = []
        if JS_URL_RE.search(transaction.url) or "javascript" in transaction.response_headers.get("content-type", ""):
            urls.append(transaction.url)
        if transaction.body and "<" in transaction.body:
            parser = ResourceParser()
            try:
                parser.feed(transaction.body)
            except Exception:
                pass
            urls.extend(parser.urls)
        transaction.script_urls = list(dict.fromkeys(urls))

    def detect(self, transaction: Transaction, signatures: Dict[str, Dict[str, Any]]) -> List[DetectionMatch]:
        self.prepare(transaction)
        matches: List[DetectionMatch] = []
        if not transaction.script_urls:
            return matches

        matched_frameworks = set()
        for framework, category, rule in self.iter_rules(signatures):
            if rule.get("type") != "script" or framework in matched_frameworks:
                continue
            pattern = rule.get("pattern")
            if not pattern:
                continue
            for url in transaction.script_urls:
                if re.search(pattern, url, re.IGNORECASE):
                    matched_frameworks.add(framework)
                    matches.append(
                        DetectionMatch(
                            framework=framework,
                            category=category,
                            confidence=int(rule.get("confidence", 50)),
                            module=self.name,
                            evidence=f"script {url}",
                            transaction_url=transaction.url,
                            transaction_source=transaction.source,
                        )
                    )
                    break
        return matches
