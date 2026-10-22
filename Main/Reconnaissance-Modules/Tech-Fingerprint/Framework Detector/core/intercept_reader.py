import json
from pathlib import Path
from typing import Iterator, List

from core.logger import get_logger
from core.models import Transaction

SUPPORTED_SUFFIXES = {".json", ".jsonl", ".ndjson", ".log"}


def _iter_source_files(intercept_path: Path) -> Iterator[Path]:
    if intercept_path.is_file():
        yield intercept_path
        return

    if intercept_path.is_dir():
        for candidate in sorted(intercept_path.rglob("*")):
            if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_SUFFIXES:
                yield candidate
        return

    raise FileNotFoundError(f"Intercept path not found: {intercept_path}")


def _parse_file(file_path: Path) -> List[dict]:
    logger = get_logger()
    raw_text = file_path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw_text:
        return []

    try:
        parsed = json.loads(raw_text)
        if isinstance(parsed, list):
            return [entry for entry in parsed if isinstance(entry, dict)]
        if isinstance(parsed, dict):
            if isinstance(parsed.get("transactions"), list):
                return [entry for entry in parsed["transactions"] if isinstance(entry, dict)]
            if isinstance(parsed.get("entries"), list):
                return [entry for entry in parsed["entries"] if isinstance(entry, dict)]
            return [parsed]
    except json.JSONDecodeError:
        pass

    records: List[dict] = []
    for line_number, line in enumerate(raw_text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            logger.warning(f"Skipping malformed JSON line {line_number} in {file_path}")
            continue
        if isinstance(entry, dict):
            records.append(entry)
    return records


def read_transactions(intercept_path: Path) -> List[Transaction]:
    logger = get_logger()
    transactions: List[Transaction] = []

    for file_path in _iter_source_files(intercept_path):
        raw_records = _parse_file(file_path)
        if not raw_records:
            logger.warning(f"No usable records found in {file_path}")
            continue

        for index, raw_record in enumerate(raw_records):
            try:
                transaction = Transaction.from_dict(raw_record, source=str(file_path), index=index)
            except Exception as error:
                logger.warning(f"Failed to parse record {index} in {file_path}: {error}")
                continue
            transactions.append(transaction)

        logger.debug(f"Loaded {len(raw_records)} record(s) from {file_path}")

    logger.info(f"Total transactions loaded: {len(transactions)}")
    return transactions
