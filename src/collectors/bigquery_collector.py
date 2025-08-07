"""
BigQuery evidence collector.
Handles interaction with BigQuery to collect audit logs and access patterns.
"""

from google.cloud import bigquery
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class BigQueryCollector:
    def __init__(self, config):
        self.config = config
        self.client = bigquery.Client()
        self.project_id = config['gcp']['project_id']
        
    def verify_connection(self):
        """Verify connection to BigQuery."""
        try:
            # Try to execute a simple query
            query = "SELECT 1"
            query_job = self.client.query(query)
            query_job.result()
            logger.info("Successfully connected to BigQuery")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to BigQuery: {e}")
            raise
            
    def collect_evidence(self):
        """Collect evidence from BigQuery audit logs."""
        evidence = {
            'access_logs': self.get_access_logs(),
            'data_access_patterns': self.get_data_access_patterns(),
            'security_configs': self.get_security_configurations()
        }
        return evidence
        
    def get_access_logs(self, days=30):
        """Collect access logs for the specified time period."""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        
        query = f"""
        SELECT
            timestamp,
            principal_email,
            method_name,
            resource_name,
            severity,
            payload
        FROM
            `{self.project_id}.audit_logs.cloudaudit_googleapis_com_activity`
        WHERE
            timestamp BETWEEN TIMESTAMP("{start_time.isoformat()}Z")
            AND TIMESTAMP("{end_time.isoformat()}Z")
        ORDER BY
            timestamp DESC
        """
        
        try:
            query_job = self.client.query(query)
            rows = query_job.result()
            
            access_logs = []
            for row in rows:
                access_logs.append({
                    'timestamp': row.timestamp,
                    'user': row.principal_email,
                    'action': row.method_name,
                    'resource': row.resource_name,
                    'severity': row.severity,
                    'details': row.payload
                })
            
            return access_logs
        except Exception as e:
            logger.error(f"Error collecting access logs: {e}")
            raise
            
    def get_data_access_patterns(self, days=30):
        """Analyze data access patterns."""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        
        query = f"""
        SELECT
            principal_email,
            resource_name,
            COUNT(*) as access_count,
            MIN(timestamp) as first_access,
            MAX(timestamp) as last_access
        FROM
            `{self.project_id}.audit_logs.cloudaudit_googleapis_com_data_access`
        WHERE
            timestamp BETWEEN TIMESTAMP("{start_time.isoformat()}Z")
            AND TIMESTAMP("{end_time.isoformat()}Z")
        GROUP BY
            principal_email,
            resource_name
        HAVING
            access_count > 1
        ORDER BY
            access_count DESC
        """
        
        try:
            query_job = self.client.query(query)
            rows = query_job.result()
            
            access_patterns = []
            for row in rows:
                access_patterns.append({
                    'user': row.principal_email,
                    'resource': row.resource_name,
                    'access_count': row.access_count,
                    'first_access': row.first_access,
                    'last_access': row.last_access
                })
            
            return access_patterns
        except Exception as e:
            logger.error(f"Error analyzing access patterns: {e}")
            raise
            
    def get_security_configurations(self):
        """Collect security configurations from BigQuery metadata."""
        query = f"""
        SELECT
            project_id,
            dataset_id,
            table_id,
            encryption_configuration,
            default_encryption_configuration
        FROM
            `{self.project_id}.region-us`.INFORMATION_SCHEMA.TABLE_OPTIONS
        """
        
        try:
            query_job = self.client.query(query)
            rows = query_job.result()
            
            security_configs = []
            for row in rows:
                security_configs.append({
                    'project': row.project_id,
                    'dataset': row.dataset_id,
                    'table': row.table_id,
                    'encryption': row.encryption_configuration,
                    'default_encryption': row.default_encryption_configuration
                })
            
            return security_configs
        except Exception as e:
            logger.error(f"Error collecting security configurations: {e}")
            raise
