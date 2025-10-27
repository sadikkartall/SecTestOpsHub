import xmltodict
import logging
from pathlib import Path
from typing import List
from models import Finding, Severity

logger = logging.getLogger(__name__)


class NmapParser:
    """Parser for Nmap XML output"""
    
    SEVERITY_MAPPING = {
        "open": "medium",
        "filtered": "low",
        "closed": "info"
    }
    
    def parse(self, xml_file: Path, scan_id: str) -> List[Finding]:
        """Parse Nmap XML output and create Finding objects"""
        findings = []
        
        try:
            with open(xml_file, 'r') as f:
                data = xmltodict.parse(f.read())
            
            nmaprun = data.get('nmaprun', {})
            hosts = nmaprun.get('host', [])
            
            # Ensure hosts is a list
            if isinstance(hosts, dict):
                hosts = [hosts]
            
            for host in hosts:
                # Get host address
                address_data = host.get('address', {})
                if isinstance(address_data, list):
                    address_data = address_data[0]
                host_addr = address_data.get('@addr', 'unknown')
                
                # Parse ports
                ports_data = host.get('ports', {})
                ports = ports_data.get('port', [])
                
                if isinstance(ports, dict):
                    ports = [ports]
                
                for port in ports:
                    port_id = port.get('@portid', 'unknown')
                    protocol = port.get('@protocol', 'tcp')
                    state = port.get('state', {}).get('@state', 'unknown')
                    
                    service = port.get('service', {})
                    service_name = service.get('@name', 'unknown')
                    service_product = service.get('@product', '')
                    service_version = service.get('@version', '')
                    
                    # Create finding
                    if state == "open":
                        title = f"Open Port: {port_id}/{protocol} - {service_name}"
                        description = f"Port {port_id}/{protocol} is open on {host_addr}."
                        
                        if service_product:
                            description += f"\nService: {service_product}"
                        if service_version:
                            description += f" {service_version}"
                        
                        # Determine severity based on port and service
                        severity = self._determine_severity(port_id, service_name)
                        
                        finding = Finding(
                            scan_id=scan_id,
                            tool="nmap",
                            title=title,
                            severity=severity,
                            endpoint=f"{host_addr}:{port_id}",
                            description=description,
                            recommendation=self._get_recommendation(service_name),
                            raw_output=port
                        )
                        
                        findings.append(finding)
            
            logger.info(f"Parsed {len(findings)} findings from Nmap output")
            return findings
            
        except Exception as e:
            logger.error(f"Error parsing Nmap output: {str(e)}")
            return []
    
    def _determine_severity(self, port: str, service: str) -> Severity:
        """Determine severity based on port and service"""
        try:
            port_num = int(port)
            
            # Critical services
            if service in ["telnet", "ftp", "rlogin", "rsh"]:
                return Severity.HIGH
            
            # Common web ports
            if port_num in [80, 443, 8080, 8443]:
                return Severity.MEDIUM
            
            # Database ports
            if port_num in [3306, 5432, 1433, 27017, 6379]:
                return Severity.HIGH
            
            # SSH
            if port_num == 22:
                return Severity.MEDIUM
            
            # RDP
            if port_num == 3389:
                return Severity.HIGH
            
            # Default
            return Severity.LOW
            
        except:
            return Severity.LOW
    
    def _get_recommendation(self, service: str) -> str:
        """Get recommendation based on service"""
        recommendations = {
            "telnet": "Telnet transmits data in plaintext. Consider using SSH instead.",
            "ftp": "FTP transmits credentials in plaintext. Consider using SFTP or FTPS.",
            "http": "HTTP traffic is unencrypted. Consider implementing HTTPS.",
            "ssh": "Ensure SSH is properly configured with key-based authentication and up-to-date.",
            "rdp": "Ensure RDP is properly secured with strong passwords and network-level authentication.",
            "mysql": "Ensure database is not exposed to the internet and uses strong authentication.",
            "postgresql": "Ensure database is not exposed to the internet and uses strong authentication.",
        }
        
        return recommendations.get(service, "Review if this service needs to be exposed and ensure it's properly secured.")

