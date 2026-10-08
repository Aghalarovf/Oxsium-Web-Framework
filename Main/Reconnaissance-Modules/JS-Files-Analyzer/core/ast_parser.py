from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


STRING_LITERAL     = re.compile(r"""(?:["'`])([^"'`\\\n]{0,512})(?:["'`])""")
FUNCTION_CALL      = re.compile(r"""([A-Za-z_$][\w$.]*)?\s*\(""")
ASSIGNMENT         = re.compile(r"""(?:var|let|const)\s+([\w$]+)\s*=\s*(.{1,256})""")
OBJECT_KEY_VALUE   = re.compile(r"""["'`]?([\w$\-]{1,64})["'`]?\s*:\s*["'`]([^"'`\n]{1,256})["'`]""")
IMPORT_REQUIRE     = re.compile(r"""(?:import\s.*?from\s*["'`]([^"'`]+)["'`]|require\s*\(\s*["'`]([^"'`]+)["'`]\s*\))""")
TEMPLATE_LITERAL   = re.compile(r"""`([^`\\]{0,1024})`""", re.DOTALL)
FUNCTION_DEF       = re.compile(r"""(?:function\s+([\w$]+)\s*\(|(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))""")
CLASS_DEF          = re.compile(r"""class\s+([\w$]+)(?:\s+extends\s+([\w$.]+))?""")
URL_IN_STRING      = re.compile(r"""["'`](https?://[^\s"'`]{4,512})["'`]""")
COMMENT_SINGLE     = re.compile(r"""//(.+)$""", re.MULTILINE)
COMMENT_MULTI      = re.compile(r"""/\*(.+?)\*/""", re.DOTALL)


@dataclass
class ASTNode:
    type:     str
    value:    str
    line:     int = 0
    children: list["ASTNode"] = field(default_factory=list)
    meta:     dict[str, Any]  = field(default_factory=dict)


@dataclass
class ParseResult:
    strings:    list[ASTNode] = field(default_factory=list)
    calls:      list[ASTNode] = field(default_factory=list)
    assignments: list[ASTNode] = field(default_factory=list)
    imports:    list[ASTNode] = field(default_factory=list)
    functions:  list[ASTNode] = field(default_factory=list)
    classes:    list[ASTNode] = field(default_factory=list)
    urls:       list[ASTNode] = field(default_factory=list)
    comments:   list[ASTNode] = field(default_factory=list)
    key_values: list[ASTNode] = field(default_factory=list)


class ASTParser:

    def __init__(self, logger: Any | None = None) -> None:
        self.logger = logger

    def parse(self, content: str) -> ParseResult:
        result = ParseResult()

        result.strings     = self._extract_strings(content)
        result.calls       = self._extract_calls(content)
        result.assignments = self._extract_assignments(content)
        result.imports     = self._extract_imports(content)
        result.functions   = self._extract_functions(content)
        result.classes     = self._extract_classes(content)
        result.urls        = self._extract_urls(content)
        result.comments    = self._extract_comments(content)
        result.key_values  = self._extract_key_values(content)

        return result

    def get_all_strings(self, result: ParseResult) -> list[str]:
        return [n.value for n in result.strings]

    def get_all_urls(self, result: ParseResult) -> list[str]:
        return [n.value for n in result.urls]

    def get_all_imports(self, result: ParseResult) -> list[str]:
        return [n.value for n in result.imports]

    def search_nodes(self, result: ParseResult, node_type: str, keyword: str) -> list[ASTNode]:
        nodes = getattr(result, node_type, [])
        keyword_lower = keyword.lower()
        return [n for n in nodes if keyword_lower in n.value.lower()]

    def _extract_strings(self, content: str) -> list[ASTNode]:
        nodes = []
        for m in STRING_LITERAL.finditer(content):
            val = m.group(1)
            if len(val) < 2:
                continue
            nodes.append(ASTNode(
                type  = "string_literal",
                value = val,
                line  = self._line(content, m.start()),
            ))
        return nodes

    def _extract_calls(self, content: str) -> list[ASTNode]:
        nodes = []
        for m in FUNCTION_CALL.finditer(content):
            name = m.group(1)
            if not name:
                continue
            nodes.append(ASTNode(
                type  = "function_call",
                value = name,
                line  = self._line(content, m.start()),
            ))
        return nodes

    def _extract_assignments(self, content: str) -> list[ASTNode]:
        nodes = []
        for m in ASSIGNMENT.finditer(content):
            nodes.append(ASTNode(
                type  = "assignment",
                value = m.group(1),
                line  = self._line(content, m.start()),
                meta  = {"rhs": m.group(2).strip()[:128]},
            ))
        return nodes

    def _extract_imports(self, content: str) -> list[ASTNode]:
        nodes = []
        for m in IMPORT_REQUIRE.finditer(content):
            val = m.group(1) or m.group(2)
            if val:
                nodes.append(ASTNode(
                    type  = "import",
                    value = val,
                    line  = self._line(content, m.start()),
                ))
        return nodes

    def _extract_functions(self, content: str) -> list[ASTNode]:
        nodes = []
        for m in FUNCTION_DEF.finditer(content):
            name = m.group(1) or m.group(2)
            if name:
                nodes.append(ASTNode(
                    type  = "function_def",
                    value = name,
                    line  = self._line(content, m.start()),
                ))
        return nodes

    def _extract_classes(self, content: str) -> list[ASTNode]:
        nodes = []
        for m in CLASS_DEF.finditer(content):
            nodes.append(ASTNode(
                type  = "class_def",
                value = m.group(1),
                line  = self._line(content, m.start()),
                meta  = {"extends": m.group(2) or ""},
            ))
        return nodes

    def _extract_urls(self, content: str) -> list[ASTNode]:
        nodes = []
        seen: set[str] = set()
        for m in URL_IN_STRING.finditer(content):
            url = m.group(1)
            if url not in seen:
                seen.add(url)
                nodes.append(ASTNode(
                    type  = "url",
                    value = url,
                    line  = self._line(content, m.start()),
                ))
        return nodes

    def _extract_comments(self, content: str) -> list[ASTNode]:
        nodes = []
        for m in COMMENT_SINGLE.finditer(content):
            nodes.append(ASTNode(
                type  = "comment",
                value = m.group(1).strip(),
                line  = self._line(content, m.start()),
                meta  = {"style": "single"},
            ))
        for m in COMMENT_MULTI.finditer(content):
            nodes.append(ASTNode(
                type  = "comment",
                value = m.group(1).strip()[:512],
                line  = self._line(content, m.start()),
                meta  = {"style": "multi"},
            ))
        return nodes

    def _extract_key_values(self, content: str) -> list[ASTNode]:
        nodes = []
        for m in OBJECT_KEY_VALUE.finditer(content):
            nodes.append(ASTNode(
                type  = "key_value",
                value = m.group(1),
                line  = self._line(content, m.start()),
                meta  = {"raw_value": m.group(2)[:256]},
            ))
        return nodes

    @staticmethod
    def _line(content: str, pos: int) -> int:
        return content[:pos].count("\n") + 1