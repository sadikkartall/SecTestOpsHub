import logging
from pathlib import Path
from typing import List
from models import Finding, Severity

logger = logging.getLogger(__name__)


def parse_amass(output_path: Path, scan_id: str) -> List[Finding]:
	"""Parse Amass discovered subdomains (txt or json) as informational findings."""
	findings: List[Finding] = []
	try:
		if not output_path.exists():
			return findings
		text = output_path.read_text(encoding="utf-8", errors="ignore")
		for line in text.splitlines():
			line = line.strip()
			if not line or line.startswith("{"):
				# basic handling; json support could be added
				continue
			f = Finding(
				scan_id=scan_id,
				tool="amass",
				title=f"Discovered subdomain: {line}",
				severity=Severity.INFO,
				description=f"Amass discovered subdomain {line}",
				recommendation="Validate subdomain ownership and assess exposure.",
			)
			findings.append(f)
		return findings
	except Exception as e:
		logger.error(f"Amass parse error: {e}")
		return []
