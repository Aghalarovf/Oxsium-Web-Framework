import json
from pathlib import Path


def export_json(data: dict, path: str = None) -> str:
    if path:
        output_path = path
    else:
        out_dir = Path(__file__).parent.parent.parent / "Scan-Results"
        out_dir.mkdir(exist_ok=True)
        output_path = str(out_dir / "dns_enum.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

    return output_path
