import sys
import json
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / 'worker'))

from parsers.trivy_parser import TrivyParser  # type: ignore


def test_trivy_parser_basic(tmp_path):
	p = tmp_path / 'trivy.json'
	data = {
		"Results": [{
			"Target": "/app",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2023-0001",
				"PkgName": "openssl",
				"InstalledVersion": "1.1.1f",
				"FixedVersion": "1.1.1u",
				"Severity": "HIGH",
				"Title": "OpenSSL vuln",
				"Description": "desc"
			}]
		}]
	}
	p.write_text(json.dumps(data), encoding='utf-8')
	parser = TrivyParser()
	findings = parser.parse(p, scan_id='scan')
	assert findings, 'should parse at least one finding'
	assert findings[0].tool == 'trivy'
