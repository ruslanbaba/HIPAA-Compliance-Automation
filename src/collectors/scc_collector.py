"""
Security Command Center evidence collector.
Handles interaction with GCP Security Command Center API to collect security findings and asset data.
"""

from google.cloud import securitycenter
from google.cloud.securitycenter_v1 import SecurityCenterClient
import logging

logger = logging.getLogger(__name__)

class SecurityCommandCenterCollector:
    def __init__(self, config):
        self.config = config
        self.client = SecurityCenterClient()
        self.project_id = config['gcp']['project_id']
        self.organization_id = config['gcp']['organization_id']
    
    def verify_connection(self):
        """Verify connection to Security Command Center."""
        try:
            organization_name = f"organizations/{self.organization_id}"
            self.client.get_organization_settings(request={"name": organization_name})
            logger.info("Successfully connected to Security Command Center")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Security Command Center: {e}")
            raise
    
    def collect_evidence(self):
        """Collect evidence from Security Command Center."""
        evidence = {
            'encryption_status': self.get_encryption_status(),
            'vulnerabilities': self.get_vulnerability_status(),
            'network_controls': self.get_network_controls(),
            'security_findings': self.get_security_findings()
        }
        return evidence
    
    def get_encryption_status(self):
        """Collect encryption status for all assets."""
        organization_name = f"organizations/{self.organization_id}"
        
        # Create finding filter for encryption-related findings
        filter_str = 'category="ENCRYPTION_STATUS"'
        
        findings = []
        request = {
            "parent": organization_name,
            "filter": filter_str
        }
        
        try:
            findings_iterator = self.client.list_findings(request)
            for finding in findings_iterator:
                findings.append({
                    'asset': finding.asset.name,
                    'status': finding.state,
                    'category': finding.category,
                    'timestamp': finding.event_time
                })
        except Exception as e:
            logger.error(f"Error collecting encryption status: {e}")
            raise
            
        return findings
    
    def get_vulnerability_status(self):
        """Collect vulnerability findings."""
        organization_name = f"organizations/{self.organization_id}"
        
        # Create filter for vulnerability findings
        filter_str = 'category="VULNERABILITY"'
        
        vulnerabilities = []
        request = {
            "parent": organization_name,
            "filter": filter_str
        }
        
        try:
            findings_iterator = self.client.list_findings(request)
            for finding in findings_iterator:
                vulnerabilities.append({
                    'asset': finding.asset.name,
                    'severity': finding.severity,
                    'category': finding.category,
                    'description': finding.description,
                    'timestamp': finding.event_time
                })
        except Exception as e:
            logger.error(f"Error collecting vulnerability status: {e}")
            raise
            
        return vulnerabilities
    
    def get_network_controls(self):
        """Collect network security controls status."""
        organization_name = f"organizations/{self.organization_id}"
        
        # Create filter for network-related findings
        filter_str = 'category="NETWORK_SECURITY"'
        
        controls = []
        request = {
            "parent": organization_name,
            "filter": filter_str
        }
        
        try:
            findings_iterator = self.client.list_findings(request)
            for finding in findings_iterator:
                controls.append({
                    'asset': finding.asset.name,
                    'status': finding.state,
                    'category': finding.category,
                    'configuration': finding.security_marks,
                    'timestamp': finding.event_time
                })
        except Exception as e:
            logger.error(f"Error collecting network controls: {e}")
            raise
            
        return controls
    
    def get_security_findings(self):
        """Collect general security findings."""
        organization_name = f"organizations/{self.organization_id}"
        
        findings = []
        request = {
            "parent": organization_name
        }
        
        try:
            findings_iterator = self.client.list_findings(request)
            for finding in findings_iterator:
                findings.append({
                    'asset': finding.asset.name,
                    'category': finding.category,
                    'severity': finding.severity,
                    'state': finding.state,
                    'description': finding.description,
                    'timestamp': finding.event_time
                })
        except Exception as e:
            logger.error(f"Error collecting security findings: {e}")
            raise
            
        return findings
