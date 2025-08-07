"""
Configuration module for the HIPAA Compliance Automation Framework.
Handles loading and validation of configuration settings.
"""

import yaml
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def load_config(config_path=None):
    """Load configuration from YAML file."""
    if config_path is None:
        config_path = Path(__file__).parent / 'config.yaml'
        
    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)
            
        validate_config(config)
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise

def validate_config(config):
    """Validate configuration settings."""
    required_sections = ['gcp', 'hipaa_controls', 'reporting']
    for section in required_sections:
        if section not in config:
            raise ValueError(f"Missing required configuration section: {section}")
            
    validate_gcp_config(config['gcp'])
    validate_hipaa_controls_config(config['hipaa_controls'])
    validate_reporting_config(config['reporting'])

def validate_gcp_config(gcp_config):
    """Validate GCP configuration settings."""
    required_fields = ['project_id', 'organization_id']
    for field in required_fields:
        if field not in gcp_config:
            raise ValueError(f"Missing required GCP configuration field: {field}")

def validate_hipaa_controls_config(controls_config):
    """Validate HIPAA controls configuration."""
    required_controls = [
        'access_control',
        'audit_controls',
        'integrity',
        'transmission_security'
    ]
    
    for control in required_controls:
        if control not in controls_config:
            raise ValueError(f"Missing required HIPAA control configuration: {control}")
            
def validate_reporting_config(reporting_config):
    """Validate reporting configuration."""
    required_fields = ['report_format', 'schedule']
    for field in required_fields:
        if field not in reporting_config:
            raise ValueError(f"Missing required reporting configuration field: {field}")
            
    if reporting_config['report_format'] not in ['pdf']:
        raise ValueError("Unsupported report format. Only 'pdf' is currently supported.")
