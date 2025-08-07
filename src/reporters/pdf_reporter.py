"""
PDF Reporter for generating compliance reports.
Creates detailed PDF reports with evidence summaries and control validations.
"""

import logging
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch

logger = logging.getLogger(__name__)

class PDFReporter:
    def __init__(self, config):
        self.config = config
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        
    def setup_custom_styles(self):
        """Setup custom paragraph and table styles."""
        self.styles.add(ParagraphStyle(
            name='Heading1',
            fontSize=16,
            spaceAfter=30
        ))
        
        self.styles.add(ParagraphStyle(
            name='Heading2',
            fontSize=14,
            spaceAfter=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='Normal',
            fontSize=10,
            spaceAfter=12
        ))
        
        self.table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ])
        
    def generate_report(self, evidence):
        """Generate PDF report from evidence."""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"hipaa_compliance_report_{timestamp}.pdf"
        
        doc = SimpleDocTemplate(
            filename,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        story = []
        
        # Add title
        story.append(Paragraph(
            "HIPAA Compliance Evidence Report",
            self.styles['Heading1']
        ))
        
        story.append(Paragraph(
            f"Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            self.styles['Normal']
        ))
        
        story.append(Spacer(1, 30))
        
        # Add executive summary
        story.extend(self.create_executive_summary(evidence))
        
        # Add control validations
        story.extend(self.create_control_validations(evidence))
        
        # Add detailed findings
        story.extend(self.create_detailed_findings(evidence))
        
        # Build the PDF
        doc.build(story)
        logger.info(f"Report generated: {filename}")
        return filename
        
    def create_executive_summary(self, evidence):
        """Create executive summary section."""
        summary = []
        
        summary.append(Paragraph(
            "Executive Summary",
            self.styles['Heading2']
        ))
        
        # Summary table data
        data = [
            ["Metric", "Value"],
            ["Total Assets Reviewed", str(evidence['summary']['total_assets_reviewed'])],
            ["Critical Findings", str(evidence['summary']['critical_findings'])],
            ["High Findings", str(evidence['summary']['high_findings'])],
            ["Encryption Compliance Rate", f"{evidence['summary']['encryption_compliance_rate']:.1f}%"],
            ["Audit Log Coverage", f"{evidence['summary']['audit_log_coverage']:.1f}%"]
        ]
        
        table = Table(data, colWidths=[4*inch, 2*inch])
        table.setStyle(self.table_style)
        
        summary.append(table)
        summary.append(Spacer(1, 20))
        
        return summary
        
    def create_control_validations(self, evidence):
        """Create control validations section."""
        validations = []
        
        validations.append(Paragraph(
            "HIPAA Control Validations",
            self.styles['Heading2']
        ))
        
        for control, details in evidence['controls'].items():
            validations.append(Paragraph(
                self.get_control_title(control),
                self.styles['Heading2']
            ))
            
            # Control status table
            data = [
                ["Status", "Issues Found", "Last Validated"],
                [
                    details['status'].upper(),
                    str(len(details['issues'])),
                    details['last_validated'].strftime('%Y-%m-%d %H:%M:%S UTC')
                ]
            ]
            
            table = Table(data, colWidths=[2*inch, 2*inch, 2*inch])
            table.setStyle(self.table_style)
            
            validations.append(table)
            validations.append(Spacer(1, 10))
            
            # Issues table if there are any
            if details['issues']:
                validations.extend(self.create_issues_table(details['issues']))
                
            validations.append(Spacer(1, 20))
            
        return validations
        
    def create_detailed_findings(self, evidence):
        """Create detailed findings section."""
        findings = []
        
        findings.append(Paragraph(
            "Detailed Findings",
            self.styles['Heading2']
        ))
        
        # SCC Findings
        findings.append(Paragraph(
            "Security Command Center Findings",
            self.styles['Heading2']
        ))
        
        scc_data = [
            ["Metric", "Count"],
            ["Critical Findings", str(evidence['details']['scc']['critical_findings'])],
            ["High Findings", str(evidence['details']['scc']['high_findings'])],
            ["Compliant Encryption", str(evidence['details']['scc']['encryption_status']['compliant'])],
            ["Non-compliant Encryption", str(evidence['details']['scc']['encryption_status']['non_compliant'])]
        ]
        
        table = Table(scc_data, colWidths=[4*inch, 2*inch])
        table.setStyle(self.table_style)
        
        findings.append(table)
        findings.append(Spacer(1, 20))
        
        # BigQuery Findings
        findings.append(Paragraph(
            "BigQuery Findings",
            self.styles['Heading2']
        ))
        
        bq_data = [
            ["Metric", "Count"],
            ["Total Access Logs", str(evidence['details']['bigquery']['total_access_logs'])],
            ["Unique Users", str(evidence['details']['bigquery']['unique_users'])],
            ["Compliant Configs", str(evidence['details']['bigquery']['security_configs']['compliant'])],
            ["Non-compliant Configs", str(evidence['details']['bigquery']['security_configs']['non_compliant'])]
        ]
        
        table = Table(bq_data, colWidths=[4*inch, 2*inch])
        table.setStyle(self.table_style)
        
        findings.append(table)
        findings.append(Spacer(1, 20))
        
        return findings
        
    def create_issues_table(self, issues):
        """Create a table for control issues."""
        elements = []
        
        data = [["Issue Type", "Count", "Details"]]
        for issue in issues:
            details_str = str(issue['details'])[:100] + "..." if len(str(issue['details'])) > 100 else str(issue['details'])
            data.append([
                issue['type'],
                str(issue['count']),
                details_str
            ])
            
        table = Table(data, colWidths=[2*inch, 1*inch, 3*inch])
        table.setStyle(self.table_style)
        
        elements.append(table)
        elements.append(Spacer(1, 10))
        
        return elements
        
    def get_control_title(self, control_key):
        """Get human-readable control title."""
        titles = {
            'access_control': 'Access Control (§164.312(a)(1))',
            'audit_controls': 'Audit Controls (§164.312(b))',
            'integrity': 'Integrity Controls (§164.312(c)(1))',
            'transmission_security': 'Transmission Security (§164.312(e)(1))'
        }
        return titles.get(control_key, control_key.replace('_', ' ').title())
