import logging
from pathlib import Path
from typing import List
from models import Finding, Severity

logger = logging.getLogger(__name__)


def parse_nikto(txt_path: Path, scan_id: str) -> List[Finding]:
	"""Very simple Nikto output parser (placeholder)."""
	findings: List[Finding] = []
	try:
		if not txt_path.exists():
			return findings
		lines = txt_path.read_text(encoding="utf-8", errors="ignore").splitlines()
		for line in lines:
			# crude heuristic: lines with 'OSVDB' or 'CVE' or 'Server leaks' considered
			if not line.strip() or line.startswith("+") is False:
				continue
			title = line.replace("+", "").strip()[:200]
			severity = Severity.LOW
			if "cve-" in line.lower():
				severity = Severity.MEDIUM
			f = Finding(
				scan_id=scan_id,
				tool="nikto",
				title=title,
				severity=severity,
				description=line.strip(),
				recommendation="Review the finding and harden web server configuration.",
				raw_output=None,
			)
			findings.append(f)
		return findings
	except Exception as e:
		logger.error(f"Nikto parse error: {e}")
		return []
