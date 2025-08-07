#!/usr/bin/env python3
"""
Main entry point for HIPAA Compliance Automation Framework.
Handles command-line interface and orchestrates the compliance evidence collection process.
"""

import argparse
import logging
from datetime import datetime

from collectors.scc_collector import SecurityCommandCenterCollector
from collectors.bigquery_collector import BigQueryCollector
from processors.evidence_processor import EvidenceProcessor
from reporters.pdf_reporter import PDFReporter
from config import load_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_framework():
    """Initialize the framework and verify all connections."""
    logger.info("Initializing HIPAA Compliance Automation Framework...")
    config = load_config()
    
    # Initialize collectors
    scc_collector = SecurityCommandCenterCollector(config)
    bq_collector = BigQueryCollector(config)
    
    # Verify connections
    scc_collector.verify_connection()
    bq_collector.verify_connection()
    
    logger.info("Framework initialized successfully!")

def collect_evidence():
    """Collect evidence from all configured sources."""
    logger.info("Starting evidence collection process...")
    config = load_config()
    
    # Initialize collectors
    scc_collector = SecurityCommandCenterCollector(config)
    bq_collector = BigQueryCollector(config)
    
    # Collect evidence
    scc_evidence = scc_collector.collect_evidence()
    bq_evidence = bq_collector.collect_evidence()
    
    # Process evidence
    processor = EvidenceProcessor(config)
    processed_evidence = processor.process_evidence(scc_evidence, bq_evidence)
    
    logger.info("Evidence collection completed!")
    return processed_evidence

def generate_report(evidence):
    """Generate PDF report from collected evidence."""
    logger.info("Generating compliance report...")
    config = load_config()
    
    reporter = PDFReporter(config)
    report_path = reporter.generate_report(evidence)
    
    logger.info(f"Report generated successfully: {report_path}")
    return report_path

def main():
    parser = argparse.ArgumentParser(description='HIPAA Compliance Automation Framework')
    parser.add_argument('command', choices=['init', 'collect', 'report'],
                      help='Command to execute')
    
    args = parser.parse_args()
    
    if args.command == 'init':
        init_framework()
    elif args.command == 'collect':
        evidence = collect_evidence()
        generate_report(evidence)
    elif args.command == 'report':
        evidence = collect_evidence()
        generate_report(evidence)

if __name__ == '__main__':
    main()
