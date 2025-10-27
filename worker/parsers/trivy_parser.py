import json
import logging
from pathlib import Path
from typing import List
from models import Finding, Severity

logger = logging.getLogger(__name__)


class TrivyParser:
    """Parser for Trivy JSON output"""
    
    SEVERITY_MAPPING = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "UNKNOWN": Severity.INFO
    }
    
    def parse(self, json_file: Path, scan_id: str) -> List[Finding]:
        """Parse Trivy JSON output and create Finding objects"""
        findings = []
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            results = data.get('Results', [])
            
            for result in results:
                target = result.get('Target', 'unknown')
                vulnerabilities = result.get('Vulnerabilities', [])
                
                if not vulnerabilities:
                    continue
                
                for vuln in vulnerabilities:
                    vuln_id = vuln.get('VulnerabilityID', 'UNKNOWN')
                    pkg_name = vuln.get('PkgName', 'unknown')
                    installed_version = vuln.get('InstalledVersion', '')
                    fixed_version = vuln.get('FixedVersion', 'Not available')
                    severity = vuln.get('Severity', 'UNKNOWN')
                    title = vuln.get('Title', '')
                    description = vuln.get('Description', '')
                    references = vuln.get('References', [])
                    
                    # CVSS Score
                    cvss_score = None
                    cvss_data = vuln.get('CVSS', {})
                    if cvss_data:
                        # Try to get CVSS v3 score first
                        if 'nvd' in cvss_data:
                            cvss_score = cvss_data['nvd'].get('V3Score') or cvss_data['nvd'].get('V2Score')
                        elif 'redhat' in cvss_data:
                            cvss_score = cvss_data['redhat'].get('V3Score') or cvss_data['redhat'].get('V2Score')
                    
                    # Build finding title
                    finding_title = f"{vuln_id}: {pkg_name} - {title if title else 'Vulnerability detected'}"
                    
                    # Build description
                    detail_desc = f"Package: {pkg_name}\n"
                    detail_desc += f"Installed Version: {installed_version}\n"
                    detail_desc += f"Fixed Version: {fixed_version}\n"
                    detail_desc += f"Severity: {severity}\n"
                    
                    if description:
                        detail_desc += f"\nDescription:\n{description}\n"
                    
                    if references:
                        detail_desc += f"\nReferences:\n"
                        for ref in references[:5]:  # Limit to 5 references
                            detail_desc += f"- {ref}\n"
                    
                    # Build recommendation
                    recommendation = f"Update {pkg_name} from version {installed_version} to {fixed_version}."
                    if fixed_version == "Not available":
                        recommendation = f"No fix is currently available for {pkg_name}. Consider using an alternative package or implementing mitigating controls."
                    
                    # Map severity
                    mapped_severity = self.SEVERITY_MAPPING.get(severity, Severity.INFO)
                    
                    finding = Finding(
                        scan_id=scan_id,
                        tool="trivy",
                        title=finding_title,
                        severity=mapped_severity,
                        cvss_score=cvss_score,
                        cve_id=vuln_id if vuln_id.startswith('CVE-') else None,
                        endpoint=target,
                        description=detail_desc,
                        recommendation=recommendation,
                        owasp_category="A06:2021 – Vulnerable and Outdated Components",
                        raw_output=vuln
                    )
                    
                    findings.append(finding)
            
            logger.info(f"Parsed {len(findings)} findings from Trivy output")
            return findings
            
        except Exception as e:
            logger.error(f"Error parsing Trivy output: {str(e)}")
            return []

