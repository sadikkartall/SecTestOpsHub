import json
import logging
from pathlib import Path
from typing import List
from models import Finding, Severity

logger = logging.getLogger(__name__)


def parse_whatweb(json_path: Path, scan_id: str) -> List[Finding]:
	"""Parse WhatWeb technology fingerprinting results as info findings."""
	findings: List[Finding] = []
	try:
		if not json_path.exists():
			return findings
		data = json.loads(json_path.read_text(encoding="utf-8", errors="ignore"))
		# Expecting a list of sites
		for site in (data if isinstance(data, list) else [data]):
			url = site.get('target') or site.get('url')
			plugins = site.get('plugins', {})
			titles = ", ".join(list(plugins.keys())[:10])
			f = Finding(
				scan_id=scan_id,
				tool="whatweb",
				title=f"WhatWeb detected: {titles}"[:500],
				severity=Severity.INFO,
				endpoint=url,
				description=f"Detected technologies: {titles}",
				recommendation="Ensure detected components are up-to-date and securely configured.",
			)
			findings.append(f)
		return findings
	except Exception as e:
		logger.error(f"WhatWeb parse error: {e}")
		return []
