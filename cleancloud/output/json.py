import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


def write_json(data: Any, output_path: Optional[Path] = None):
    class DataclassEncoder(json.JSONEncoder):
        def default(self, o):
            if is_dataclass(o):
                return asdict(o)
            if isinstance(o, datetime):
                return o.isoformat()
            return super().default(o)

    json_str = json.dumps(data, indent=2, cls=DataclassEncoder)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
    else:
        return json_str
