import json
import logging
from pathlib import Path
from typing import List
from models import Finding, Severity

logger = logging.getLogger(__name__)


class ZapParser:
    """Parser for OWASP ZAP JSON output"""
    
    RISK_TO_SEVERITY = {
        "Informational": Severity.INFO,
        "Low": Severity.LOW,
        "Medium": Severity.MEDIUM,
        "High": Severity.HIGH
    }
    
    OWASP_MAPPING = {
        "SQL Injection": "A03:2021 – Injection",
        "Cross Site Scripting": "A03:2021 – Injection",
        "Path Traversal": "A01:2021 – Broken Access Control",
        "Remote File Inclusion": "A03:2021 – Injection",
        "Cross-Site Request Forgery": "A01:2021 – Broken Access Control",
        "Cookie Without Secure Flag": "A05:2021 – Security Misconfiguration",
        "X-Frame-Options Header Not Set": "A05:2021 – Security Misconfiguration",
        "X-Content-Type-Options Header Missing": "A05:2021 – Security Misconfiguration",
        "Content Security Policy": "A05:2021 – Security Misconfiguration",
    }
    
    def parse(self, json_file: Path, scan_id: str) -> List[Finding]:
        """Parse ZAP JSON output and create Finding objects"""
        findings = []
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            site = data.get('site', [])
            if isinstance(site, dict):
                site = [site]
            
            for site_data in site:
                alerts = site_data.get('alerts', [])
                
                for alert in alerts:
                    alert_name = alert.get('name', 'Unknown Alert')
                    risk = alert.get('riskdesc', 'Low').split()[0]  # "Low (Medium)" -> "Low"
                    description = alert.get('desc', '')
                    solution = alert.get('solution', '')
                    reference = alert.get('reference', '')
                    
                    # Get instances (specific URLs where the issue was found)
                    instances = alert.get('instances', [])
                    
                    if not instances:
                        # No specific instances, create one general finding
                        instances = [{'uri': site_data.get('@name', 'unknown')}]
                    
                    for instance in instances:
                        uri = instance.get('uri', 'unknown')
                        method = instance.get('method', '')
                        param = instance.get('param', '')
                        evidence = instance.get('evidence', '')
                        
                        # Build title
                        title = alert_name
                        if param:
                            title += f" (Parameter: {param})"
                        
                        # Build detailed description
                        detail_desc = description
                        if method:
                            detail_desc += f"\n\nHTTP Method: {method}"
                        if evidence:
                            detail_desc += f"\nEvidence: {evidence[:200]}"
                        if reference:
                            detail_desc += f"\n\nReferences:\n{reference}"
                        
                        # Map to OWASP Top 10
                        owasp_category = self._map_to_owasp(alert_name)
                        
                        # Determine severity
                        severity = self.RISK_TO_SEVERITY.get(risk, Severity.MEDIUM)
                        
                        finding = Finding(
                            scan_id=scan_id,
                            tool="zap",
                            title=title,
                            severity=severity,
                            endpoint=uri,
                            description=detail_desc,
                            recommendation=solution,
                            owasp_category=owasp_category,
                            raw_output=alert
                        )
                        
                        findings.append(finding)
            
            logger.info(f"Parsed {len(findings)} findings from ZAP output")
            return findings
            
        except Exception as e:
            logger.error(f"Error parsing ZAP output: {str(e)}")
            return []
    
    def _map_to_owasp(self, alert_name: str) -> str:
        """Map ZAP alert to OWASP Top 10 2021 category"""
        for key, category in self.OWASP_MAPPING.items():
            if key.lower() in alert_name.lower():
                return category
        
        # Default mapping
        return "A05:2021 – Security Misconfiguration"

