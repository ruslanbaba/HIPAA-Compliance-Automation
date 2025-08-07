import unittest
from unittest.mock import patch, MagicMock
from src.collectors.scc_collector import SecurityCommandCenterCollector
from src.collectors.bigquery_collector import BigQueryCollector
from src.processors.evidence_processor import EvidenceProcessor

class TestCollectEvidence(unittest.TestCase):
    @patch('src.collectors.scc_collector.SecurityCommandCenterCollector')
    @patch('src.collectors.bigquery_collector.BigQueryCollector')
    def test_collect_hipaa_evidence(self, mock_bq_collector, mock_scc_collector):
        # Mock configuration
        config = {
            'gcp': {
                'project_id': 'test-project-id',
                'organization_id': 'test-org-id'
            }
        }
        
        # Setup mock collectors
        mock_scc = MagicMock()
        mock_bq = MagicMock()
        
        mock_scc_collector.return_value = mock_scc
        mock_bq_collector.return_value = mock_bq
        
        # Mock evidence data
        mock_scc.collect_evidence.return_value = {
            'security_findings': [],
            'encryption_status': [],
            'network_controls': []
        }
        
        mock_bq.collect_evidence.return_value = {
            'access_logs': [],
            'data_access_patterns': [],
            'security_configs': []
        }
        
        # Create evidence processor
        processor = EvidenceProcessor(config)
        
        # Process evidence
        evidence = processor.process_evidence(
            mock_scc.collect_evidence(),
            mock_bq.collect_evidence()
        )
        
        # Assertions
        self.assertIsNotNone(evidence)
        self.assertIn('controls', evidence)
        self.assertIn('summary', evidence)
        self.assertIn('details', evidence)
        
        # Verify collector calls
        mock_scc.collect_evidence.assert_called_once()
        mock_bq.collect_evidence.assert_called_once()

if __name__ == '__main__':
    unittest.main()
