import json
import markdown
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from io import BytesIO
import logging

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from models import Scan, Finding, Target

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate security scan reports in various formats"""
    
    def __init__(self, scan: Scan, target: Target, findings: List[Finding]):
        self.scan = scan
        self.target = target
        self.findings = findings
        self.timestamp = datetime.utcnow()
    
    def generate_json(self) -> str:
        """Generate JSON report"""
        report = {
            "report_metadata": {
                "generated_at": self.timestamp.isoformat(),
                "scan_id": str(self.scan.id),
                "target": {
                    "id": str(self.target.id),
                    "url": self.target.url,
                    "description": self.target.description
                },
                "scan_info": {
                    "tools": self.scan.tools,
                    "status": self.scan.status.value,
                    "started_at": self.scan.started_at.isoformat() if self.scan.started_at else None,
                    "finished_at": self.scan.finished_at.isoformat() if self.scan.finished_at else None
                }
            },
            "summary": self._generate_summary(),
            "findings": [
                {
                    "id": str(f.id),
                    "tool": f.tool,
                    "title": f.title,
                    "severity": f.severity.value,
                    "cvss_score": f.cvss_score,
                    "cve_id": f.cve_id,
                    "owasp_category": f.owasp_category,
                    "endpoint": f.endpoint,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "ai_summary": f.ai_summary,
                    "ai_recommendation": f.ai_recommendation,
                    "probable_fp": f.probable_fp,
                    "created_at": f.created_at.isoformat()
                }
                for f in self.findings
            ]
        }
        return json.dumps(report, indent=2)
    
    def generate_markdown(self) -> str:
        """Generate Markdown report"""
        md = []
        
        # Header
        md.append("# SecTestOps Hub - Security Scan Report")
        md.append(f"\n**Generated:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        md.append(f"\n**Scan ID:** `{self.scan.id}`")
        md.append(f"\n**Target:** {self.target.url}")
        md.append(f"\n**Description:** {self.target.description or 'N/A'}")
        md.append("\n---\n")
        
        # Summary
        summary = self._generate_summary()
        md.append("## Executive Summary\n")
        md.append(f"- **Total Findings:** {summary['total_findings']}")
        md.append(f"- **Critical:** {summary['severity_counts']['critical']}")
        md.append(f"- **High:** {summary['severity_counts']['high']}")
        md.append(f"- **Medium:** {summary['severity_counts']['medium']}")
        md.append(f"- **Low:** {summary['severity_counts']['low']}")
        md.append(f"- **Info:** {summary['severity_counts']['info']}")
        md.append(f"\n**Tools Used:** {', '.join(self.scan.tools)}")
        
        if self.scan.started_at and self.scan.finished_at:
            duration = (self.scan.finished_at - self.scan.started_at).total_seconds()
            md.append(f"\n**Scan Duration:** {int(duration)} seconds")
        
        md.append("\n---\n")
        
        # Findings by Severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            severity_findings = [f for f in self.findings if f.severity.value == severity]
            if severity_findings:
                md.append(f"\n## {severity.upper()} Severity Findings ({len(severity_findings)})\n")
                
                for idx, finding in enumerate(severity_findings, 1):
                    md.append(f"\n### {idx}. {finding.title}\n")
                    md.append(f"**Tool:** {finding.tool.upper()}")
                    
                    if finding.cvss_score:
                        md.append(f" | **CVSS Score:** {finding.cvss_score}")
                    if finding.cve_id:
                        md.append(f" | **CVE:** {finding.cve_id}")
                    if finding.owasp_category:
                        md.append(f"\n**OWASP Category:** {finding.owasp_category}")
                    if finding.endpoint:
                        md.append(f"\n**Endpoint:** `{finding.endpoint}`")
                    
                    if finding.description:
                        md.append(f"\n**Description:**\n{finding.description}")
                    
                    if finding.ai_summary:
                        md.append(f"\n**AI Analysis:**\n> {finding.ai_summary}")
                        if finding.ai_recommendation:
                            md.append(f"\n> **AI Recommendation:** {finding.ai_recommendation}")
                        if finding.probable_fp:
                            md.append("\n> ⚠️ **Note:** This may be a false positive")
                    
                    if finding.recommendation:
                        md.append(f"\n**Remediation:**\n{finding.recommendation}")
                    
                    md.append("\n---\n")
        
        # Footer
        md.append("\n## Report Information\n")
        md.append("This report was automatically generated by **SecTestOps Hub**.")
        md.append("\nFor more information, visit the SecTestOps Hub dashboard.")
        
        return "\n".join(md)
    
    def generate_pdf(self) -> BytesIO:
        """Generate PDF report"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1976d2'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = styles['Heading2']
        normal_style = styles['Normal']
        
        # Title
        elements.append(Paragraph("SecTestOps Hub", title_style))
        elements.append(Paragraph("Security Scan Report", title_style))
        elements.append(Spacer(1, 12))
        
        # Metadata
        metadata = [
            ["Generated:", self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ["Scan ID:", str(self.scan.id)[:16] + "..."],
            ["Target:", self.target.url],
            ["Tools:", ", ".join([t.upper() for t in self.scan.tools])],
        ]
        
        if self.target.description:
            metadata.append(["Description:", self.target.description[:60]])
        
        t = Table(metadata, colWidths=[2*inch, 4*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.grey),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(t)
        elements.append(Spacer(1, 20))
        
        # Summary
        summary = self._generate_summary()
        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(Spacer(1, 12))
        
        summary_data = [
            ["Severity", "Count"],
            ["Critical", str(summary['severity_counts']['critical'])],
            ["High", str(summary['severity_counts']['high'])],
            ["Medium", str(summary['severity_counts']['medium'])],
            ["Low", str(summary['severity_counts']['low'])],
            ["Info", str(summary['severity_counts']['info'])],
            ["TOTAL", str(summary['total_findings'])],
        ]
        
        t = Table(summary_data, colWidths=[3*inch, 2*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 1), (1, 1), colors.red),  # Critical
            ('BACKGROUND', (1, 2), (1, 2), colors.orange),  # High
            ('BACKGROUND', (1, 3), (1, 3), colors.yellow),  # Medium
            ('BACKGROUND', (1, 4), (1, 4), colors.lightgreen),  # Low
            ('BACKGROUND', (1, 5), (1, 5), colors.lightblue),  # Info
            ('BACKGROUND', (0, 6), (-1, 6), colors.grey),  # Total
            ('TEXTCOLOR', (0, 6), (-1, 6), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(t)
        elements.append(PageBreak())
        
        # Findings
        elements.append(Paragraph("Detailed Findings", heading_style))
        elements.append(Spacer(1, 12))
        
        for idx, finding in enumerate(self.findings, 1):
            # Finding header
            finding_title = f"{idx}. [{finding.severity.value.upper()}] {finding.title[:80]}"
            elements.append(Paragraph(finding_title, styles['Heading3']))
            elements.append(Spacer(1, 6))
            
            # Finding details
            finding_data = [
                ["Tool", finding.tool.upper()],
                ["Severity", finding.severity.value.upper()],
            ]
            
            if finding.endpoint:
                finding_data.append(["Endpoint", finding.endpoint[:60]])
            if finding.cvss_score:
                finding_data.append(["CVSS Score", str(finding.cvss_score)])
            if finding.cve_id:
                finding_data.append(["CVE ID", finding.cve_id])
            if finding.owasp_category:
                finding_data.append(["OWASP", finding.owasp_category[:40]])
            
            t = Table(finding_data, colWidths=[1.5*inch, 4.5*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            elements.append(t)
            elements.append(Spacer(1, 10))
            
            # Description
            if finding.description:
                desc_text = finding.description[:500] + "..." if len(finding.description) > 500 else finding.description
                elements.append(Paragraph("<b>Description:</b>", normal_style))
                elements.append(Paragraph(desc_text.replace('\n', '<br/>'), normal_style))
                elements.append(Spacer(1, 10))
            
            # Recommendation
            if finding.recommendation:
                rec_text = finding.recommendation[:300] + "..." if len(finding.recommendation) > 300 else finding.recommendation
                elements.append(Paragraph("<b>Recommendation:</b>", normal_style))
                elements.append(Paragraph(rec_text.replace('\n', '<br/>'), normal_style))
            
            elements.append(Spacer(1, 20))
        
        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        return buffer
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        tool_counts = {}
        owasp_counts = {}
        
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
            
            tool = finding.tool
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
            
            if finding.owasp_category:
                owasp = finding.owasp_category
                owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1
        
        return {
            'total_findings': len(self.findings),
            'severity_counts': severity_counts,
            'tool_counts': tool_counts,
            'owasp_counts': owasp_counts
        }

