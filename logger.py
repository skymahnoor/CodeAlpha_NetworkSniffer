"""
logger.py
---------
Persists captured packet data and alerts to disk so a session can be
reviewed later -- useful for the LinkedIn/video demo and for showing
"evidence" of the tool actually working, not just live terminal output.
"""

import csv
import json
import os
from datetime import datetime


class SessionLogger:
    """Buffers packet records and alerts in memory, writes them out
    as JSON and CSV when the session ends."""

    def __init__(self, output_dir: str = "logs"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.json_path = os.path.join(self.output_dir, f"capture_{timestamp}.json")
        self.csv_path = os.path.join(self.output_dir, f"capture_{timestamp}.csv")
        self._records = []

    def record(self, info: dict, alerts: list[str]):
        entry = dict(info)
        entry["alerts"] = alerts
        self._records.append(entry)

    def flush(self):
        """Write all buffered records to JSON and CSV files."""
        with open(self.json_path, "w") as f:
            json.dump(self._records, f, indent=2)

        if self._records:
            fieldnames = list(self._records[0].keys())
            with open(self.csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for row in self._records:
                    row_copy = dict(row)
                    row_copy["alerts"] = "; ".join(row_copy.get("alerts", []))
                    writer.writerow(row_copy)

        return self.json_path, self.csv_path
