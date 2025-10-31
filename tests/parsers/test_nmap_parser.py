import sys
from pathlib import Path

# allow importing worker package modules
sys.path.append(str(Path(__file__).resolve().parents[1] / 'worker'))

from parsers.nmap_parser import NmapParser  # type: ignore


def test_nmap_parser_basic(tmp_path):
	xml = tmp_path / 'nmap.xml'
	xml.write_text("""<?xml version='1.0'?>
<nmaprun>
  <host>
    <address addr="127.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
    </ports>
  </host>
</nmaprun>
""", encoding='utf-8')
	parser = NmapParser()
	findings = parser.parse(xml, scan_id='test-scan')
	assert findings, 'parser should return at least one finding'
	f = findings[0]
	assert f.tool == 'nmap'
	assert 'Open Port' in f.title
