"""
Evidence processor for correlating and analyzing collected compliance data.
Maps raw evidence to HIPAA controls and validates compliance status.
"""

import logging
from datetime import datetime
import pandas as pd

logger = logging.getLogger(__name__)

class EvidenceProcessor:
    def __init__(self, config):
        self.config = config
        self.control_mappings = config['hipaa_controls']
        
    def process_evidence(self, scc_evidence, bq_evidence):
        """Process and correlate evidence from all sources."""
        processed_evidence = {
            'timestamp': datetime.utcnow(),
            'controls': self.map_to_hipaa_controls(scc_evidence, bq_evidence),
            'summary': self.generate_summary(scc_evidence, bq_evidence),
            'details': {
                'scc': self.process_scc_evidence(scc_evidence),
                'bigquery': self.process_bq_evidence(bq_evidence)
            }
        }
        return processed_evidence
        
    def map_to_hipaa_controls(self, scc_evidence, bq_evidence):
        """Map evidence to HIPAA controls."""
        controls = {}
        
        # Access Control (§164.312(a)(1))
        controls['access_control'] = self.validate_access_control(
            scc_evidence['security_findings'],
            bq_evidence['access_logs']
        )
        
        # Audit Controls (§164.312(b))
        controls['audit_controls'] = self.validate_audit_controls(
            bq_evidence['access_logs'],
            bq_evidence['data_access_patterns']
        )
        
        # Integrity (§164.312(c)(1))
        controls['integrity'] = self.validate_integrity(
            scc_evidence['security_findings'],
            scc_evidence['encryption_status']
        )
        
        # Transmission Security (§164.312(e)(1))
        controls['transmission_security'] = self.validate_transmission_security(
            scc_evidence['network_controls'],
            scc_evidence['encryption_status']
        )
        
        return controls
    
    def validate_access_control(self, security_findings, access_logs):
        """Validate access control requirements."""
        issues = []
        status = 'compliant'
        
        # Check for unauthorized access attempts
        unauthorized_access = [
            log for log in access_logs
            if log['severity'] in ['ERROR', 'WARNING']
            and 'permission denied' in str(log['details']).lower()
        ]
        
        if unauthorized_access:
            issues.append({
                'type': 'unauthorized_access',
                'count': len(unauthorized_access),
                'details': unauthorized_access[:5]  # Include first 5 examples
            })
            status = 'non_compliant'
            
        # Check security findings related to IAM
        iam_findings = [
            finding for finding in security_findings
            if 'iam' in finding['category'].lower()
            and finding['severity'] in ['HIGH', 'CRITICAL']
        ]
        
        if iam_findings:
            issues.append({
                'type': 'iam_issues',
                'count': len(iam_findings),
                'details': iam_findings[:5]
            })
            status = 'non_compliant'
            
        return {
            'status': status,
            'issues': issues,
            'last_validated': datetime.utcnow()
        }
    
    def validate_audit_controls(self, access_logs, access_patterns):
        """Validate audit control requirements."""
        issues = []
        status = 'compliant'
        
        # Check for gaps in audit logging
        df_logs = pd.DataFrame(access_logs)
        if not df_logs.empty:
            df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])
            time_gaps = df_logs.sort_values('timestamp')['timestamp'].diff()
            significant_gaps = time_gaps[time_gaps > pd.Timedelta(hours=1)]
            
            if not significant_gaps.empty:
                issues.append({
                    'type': 'audit_log_gaps',
                    'count': len(significant_gaps),
                    'details': significant_gaps.head().to_dict()
                })
                status = 'non_compliant'
        
        # Check for unusual access patterns
        suspicious_patterns = [
            pattern for pattern in access_patterns
            if pattern['access_count'] > 100  # Threshold for suspicious activity
        ]
        
        if suspicious_patterns:
            issues.append({
                'type': 'suspicious_access_patterns',
                'count': len(suspicious_patterns),
                'details': suspicious_patterns[:5]
            })
            status = 'warning'
            
        return {
            'status': status,
            'issues': issues,
            'last_validated': datetime.utcnow()
        }
    
    def validate_integrity(self, security_findings, encryption_status):
        """Validate integrity requirements."""
        issues = []
        status = 'compliant'
        
        # Check encryption status
        unencrypted_assets = [
            asset for asset in encryption_status
            if asset['status'] != 'ACTIVE'
        ]
        
        if unencrypted_assets:
            issues.append({
                'type': 'unencrypted_assets',
                'count': len(unencrypted_assets),
                'details': unencrypted_assets[:5]
            })
            status = 'non_compliant'
        
        # Check integrity-related security findings
        integrity_findings = [
            finding for finding in security_findings
            if 'integrity' in finding['category'].lower()
            and finding['severity'] in ['HIGH', 'CRITICAL']
        ]
        
        if integrity_findings:
            issues.append({
                'type': 'integrity_issues',
                'count': len(integrity_findings),
                'details': integrity_findings[:5]
            })
            status = 'non_compliant'
            
        return {
            'status': status,
            'issues': issues,
            'last_validated': datetime.utcnow()
        }
    
    def validate_transmission_security(self, network_controls, encryption_status):
        """Validate transmission security requirements."""
        issues = []
        status = 'compliant'
        
        # Check network controls
        insecure_networks = [
            control for control in network_controls
            if control['status'] != 'ACTIVE'
        ]
        
        if insecure_networks:
            issues.append({
                'type': 'insecure_networks',
                'count': len(insecure_networks),
                'details': insecure_networks[:5]
            })
            status = 'non_compliant'
        
        # Check encryption in transit
        transit_encryption = [
            asset for asset in encryption_status
            if 'transit' in str(asset).lower()
            and asset['status'] != 'ACTIVE'
        ]
        
        if transit_encryption:
            issues.append({
                'type': 'transit_encryption_issues',
                'count': len(transit_encryption),
                'details': transit_encryption[:5]
            })
            status = 'non_compliant'
            
        return {
            'status': status,
            'issues': issues,
            'last_validated': datetime.utcnow()
        }
    
    def process_scc_evidence(self, scc_evidence):
        """Process Security Command Center evidence."""
        return {
            'critical_findings': len([
                f for f in scc_evidence['security_findings']
                if f['severity'] == 'CRITICAL'
            ]),
            'high_findings': len([
                f for f in scc_evidence['security_findings']
                if f['severity'] == 'HIGH'
            ]),
            'encryption_status': {
                'compliant': len([
                    e for e in scc_evidence['encryption_status']
                    if e['status'] == 'ACTIVE'
                ]),
                'non_compliant': len([
                    e for e in scc_evidence['encryption_status']
                    if e['status'] != 'ACTIVE'
                ])
            }
        }
    
    def process_bq_evidence(self, bq_evidence):
        """Process BigQuery evidence."""
        return {
            'total_access_logs': len(bq_evidence['access_logs']),
            'unique_users': len(set(
                log['user'] for log in bq_evidence['access_logs']
            )),
            'security_configs': {
                'compliant': len([
                    c for c in bq_evidence['security_configs']
                    if c['encryption'] is not None
                ]),
                'non_compliant': len([
                    c for c in bq_evidence['security_configs']
                    if c['encryption'] is None
                ])
            }
        }
    
    def generate_summary(self, scc_evidence, bq_evidence):
        """Generate overall compliance summary."""
        return {
            'total_assets_reviewed': len(scc_evidence['security_findings']),
            'critical_findings': len([
                f for f in scc_evidence['security_findings']
                if f['severity'] == 'CRITICAL'
            ]),
            'high_findings': len([
                f for f in scc_evidence['security_findings']
                if f['severity'] == 'HIGH'
            ]),
            'encryption_compliance_rate': self.calculate_encryption_rate(
                scc_evidence['encryption_status']
            ),
            'audit_log_coverage': self.calculate_audit_coverage(
                bq_evidence['access_logs']
            )
        }
    
    def calculate_encryption_rate(self, encryption_status):
        """Calculate encryption compliance rate."""
        total = len(encryption_status)
        if total == 0:
            return 0
            
        compliant = len([
            e for e in encryption_status
            if e['status'] == 'ACTIVE'
        ])
        
        return (compliant / total) * 100
    
    def calculate_audit_coverage(self, access_logs):
        """Calculate audit log coverage percentage."""
        if not access_logs:
            return 0
            
        df_logs = pd.DataFrame(access_logs)
        df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])
        
        total_duration = (df_logs['timestamp'].max() - df_logs['timestamp'].min())
        total_hours = total_duration.total_seconds() / 3600
        
        if total_hours == 0:
            return 0
            
        coverage_hours = total_hours - sum(
            gap.total_seconds() / 3600
            for gap in df_logs.sort_values('timestamp')['timestamp'].diff()
            if gap and gap.total_seconds() > 3600  # Gaps longer than 1 hour
        )
        
        return (coverage_hours / total_hours) * 100
