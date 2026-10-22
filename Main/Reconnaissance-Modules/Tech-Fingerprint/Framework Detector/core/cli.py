import argparse
import json
import sys
from pathlib import Path
from typing import List

from core.engine import DetectionEngine
from core.logger import build_logger
from core.models import DetectionResult

DEFAULT_SIGNATURES_DIR = Path(__file__).resolve().parent.parent / "signatures"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="framework_detector",
        description="Passive framework and technology detector driven by intercepted HTTP traffic",
    )
    parser.add_argument(
        "--intercept",
        required=True,
        type=Path,
        help="Path to an intercepted traffic JSON/JSONL file or a directory containing such files",
    )
    parser.add_argument(
        "--signatures",
        type=Path,
        default=DEFAULT_SIGNATURES_DIR,
        help="Directory containing signature JSON files (default: ./signatures)",
    )
    parser.add_argument(
        "--executor",
        choices=["process", "thread"],
        default="process",
        help="Parallel backend, one task per signature file (default: process; threads are GIL-bound)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Max workers (default: CPU count for process, one per signature file for thread)",
    )
    parser.add_argument(
        "--min-confidence",
        type=int,
        default=0,
        help="Only show results with confidence greater than or equal to this value (default: 0)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write output to this file instead of stdout",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )
    return parser


def render_text(results: List[DetectionResult]) -> str:
    if not results:
        return "No frameworks detected from the provided traffic."

    lines = []
    lines.append(f"{'FRAMEWORK':<25}{'CATEGORY':<15}{'CONFIDENCE':<12}{'HITS':<6}MODULES")
    lines.append("-" * 90)
    for result in results:
        modules_joined = ", ".join(result.modules)
        lines.append(
            f"{result.framework:<25}{result.category:<15}{str(result.confidence) + '%':<12}"
            f"{result.occurrences:<6}{modules_joined}"
        )
        for evidence in result.evidence:
            lines.append(f"    - {evidence}")
    return "\n".join(lines)


def render_json(results: List[DetectionResult]) -> str:
    return json.dumps([result.to_dict() for result in results], indent=2, ensure_ascii=False)


def main(argv: List[str] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logger = build_logger(verbose=args.verbose)

    try:
        engine = DetectionEngine(signatures_path=args.signatures, max_workers=args.workers, executor=args.executor)
        results = engine.run(args.intercept)
    except FileNotFoundError as error:
        logger.error(str(error))
        return 1
    except Exception as error:
        logger.error(f"Unexpected failure during detection: {error}")
        return 1

    filtered_results = [result for result in results if result.confidence >= args.min_confidence]

    if args.format == "json":
        output_text = render_json(filtered_results)
    else:
        output_text = render_text(filtered_results)

    if args.output:
        args.output.write_text(output_text + "\n", encoding="utf-8")
        logger.info(f"Results written to {args.output}")
    else:
        sys.stdout.write(output_text + "\n")

    return 0
