import json
import logging
from pathlib import Path
from typing import List
from models import Finding, Severity

logger = logging.getLogger(__name__)


def parse_ffuf(json_path: Path, scan_id: str) -> List[Finding]:
	"""Parse ffuf JSON output for discovered endpoints."""
	findings: List[Finding] = []
	try:
		if not json_path.exists():
			return findings
		data = json.loads(json_path.read_text(encoding="utf-8", errors="ignore"))
		results = data.get("results", [])
		for r in results:
			url = r.get("url") or r.get("redirectlocation")
			status = r.get("status")
			size = r.get("length")
			title = f"ffuf discovered endpoint: {url} ({status})"
			f = Finding(
				scan_id=scan_id,
				tool="ffuf",
				title=title[:500],
				severity=Severity.LOW,
				endpoint=url,
				description=f"Status {status}, length {size}",
				recommendation="Review discovered endpoint and restrict access if unnecessary.",
			)
			findings.append(f)
		return findings
	except Exception as e:
		logger.error(f"ffuf parse error: {e}")
		return []
