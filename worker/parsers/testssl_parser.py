import json
import logging
from pathlib import Path
from typing import List
from models import Finding, Severity

logger = logging.getLogger(__name__)


def parse_testssl(json_path: Path, scan_id: str) -> List[Finding]:
	"""Parse testssl.sh JSON report to findings."""
	findings: List[Finding] = []
	try:
		if not json_path.exists():
			return findings
		data = json.loads(json_path.read_text(encoding="utf-8", errors="ignore"))
		for item in data.get("scanResult", []):
			id_ = item.get("id", "TLS")
			severity = Severity.MEDIUM
			if "SSLv2" in id_ or "SSLv3" in id_ or "RC4" in id_:
				severity = Severity.HIGH
			desc = item.get("finding", "")
			f = Finding(
				scan_id=scan_id,
				tool="testssl",
				title=f"TLS Finding: {id_}"[:500],
				severity=severity,
				description=desc,
				recommendation="Disable insecure protocols/ciphers and enable modern TLS settings.",
			)
			findings.append(f)
		return findings
	except Exception as e:
		logger.error(f"testssl parse error: {e}")
		return []
