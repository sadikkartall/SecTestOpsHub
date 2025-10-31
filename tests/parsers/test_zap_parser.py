import sys
import json
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / 'worker'))

from parsers.zap_parser import ZapParser  # type: ignore


def test_zap_parser_basic(tmp_path):
	p = tmp_path / 'zap.json'
	data = {
		"site": [{
			"@name": "http://localhost",
			"alerts": [{
				"name": "X-Content-Type-Options Header Missing",
				"riskdesc": "Low (Medium)",
				"desc": "header missing",
				"solution": "add header",
				"instances": [{"uri": "http://localhost/", "method": "GET"}]
			}]
		}]
	}
	p.write_text(json.dumps(data), encoding='utf-8')
	parser = ZapParser()
	findings = parser.parse(p, scan_id='scan')
	assert findings, 'should parse at least one finding'
	assert findings[0].tool == 'zap'
