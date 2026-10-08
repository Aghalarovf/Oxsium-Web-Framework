"""Helpers for walking decoded (JSON-like) cookie payloads."""

from typing import Any, List, Tuple

MAX_LEAVES = 500


def flatten(obj: Any, prefix: str = "") -> Tuple[List[Tuple[str, Any]], int]:
    """Flatten a nested dict/list structure into (path, leaf_value) pairs.

    Returns (leaves, max_depth). Paths look like "user.id" or "items[0].name".
    Traversal stops once MAX_LEAVES is hit to keep this bounded on hostile input.
    """
    leaves: List[Tuple[str, Any]] = []

    def _walk(node: Any, path: str, depth: int) -> int:
        if len(leaves) >= MAX_LEAVES:
            return depth
        if isinstance(node, dict):
            deepest = depth
            for key, value in node.items():
                child_path = f"{path}.{key}" if path else str(key)
                deepest = max(deepest, _walk(value, child_path, depth + 1))
                if len(leaves) >= MAX_LEAVES:
                    break
            return deepest
        if isinstance(node, (list, tuple)):
            deepest = depth
            for index, value in enumerate(node):
                child_path = f"{path}[{index}]"
                deepest = max(deepest, _walk(value, child_path, depth + 1))
                if len(leaves) >= MAX_LEAVES:
                    break
            return deepest
        leaves.append((path, node))
        return depth

    max_depth = _walk(obj, prefix, 0)
    return leaves, max_depth
