# HIPAA Compliance Automation Framework

## Overview
This Python-based framework automates the collection, correlation, and reporting of HIPAA compliance evidence from Google Cloud Platform (GCP) infrastructure. It leverages GCP Security Command Center API and BigQuery to monitor and validate 50+ technical HIPAA controls, significantly reducing the manual effort required for annual HIPAA audits.

## Key Features
- **Automated Evidence Collection**: Continuously gathers data for 50+ technical HIPAA controls
- **Comprehensive Coverage**:
  - Encryption status monitoring
  - Access logs analysis
  - Vulnerability assessment
  - Network security controls
  - IAM policies and permissions
  - Security configurations
- **Automated Reporting**: Generates scheduled PDF reports for auditors
- **Time Efficiency**: Reduces manual evidence gathering time by 60%
- **Improved Validation**: Enhanced control validation frequency

## Project Structure
```
src/
├── collectors/
│   ├── scc_collector.py      # Security Command Center data collector
│   └── bigquery_collector.py # BigQuery logs and audit data collector
├── processors/
│   └── evidence_processor.py # Evidence correlation and analysis
├── reporters/
│   └── pdf_reporter.py      # PDF report generation
├── config.py               # Configuration management
├── config.yaml            # Configuration settings
└── main.py               # Main application entry point
```

## Technical Architecture
### Components
1. **Data Collectors**
   - GCP Security Command Center API integration
   - BigQuery data extraction
   - Cloud Logging integration

2. **Evidence Processors**
   - Data correlation engine
   - Compliance mapping logic
   - Evidence validation rules

3. **Reporting Engine**
   - PDF report generation
   - Evidence visualization
   - Control status dashboard

### Technology Stack
- Python 3.8+
- Google Cloud Platform
  - Security Command Center
  - BigQuery
  - Cloud Functions
  - Cloud Scheduler
- pandas for data processing
- reportlab for PDF generation

## Prerequisites
1. Google Cloud Platform project with:
   - Security Command Center enabled
   - BigQuery API enabled
   - Appropriate IAM permissions
2. Python 3.8 or higher
3. Required Python packages (see requirements.txt)

## Setup and Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/hipaa-compliance-automation.git
   cd hipaa-compliance-automation
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure GCP credentials:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/credentials.json"
   ```

5. Update configuration in `src/config.yaml`:
   - Set your GCP project ID
   - Set your organization ID
   - Configure notification settings

## Usage
1. **Initialize the framework**:
   ```bash
   python src/main.py init
   ```

2. **Run evidence collection**:
   ```bash
   python src/main.py collect
   ```

3. **Generate compliance report**:
   ```bash
   python src/main.py report
   ```

## HIPAA Controls Coverage
The framework covers various HIPAA technical safeguards including:
- Access Control (§164.312(a)(1))
  - Unique user identification
  - Emergency access procedures
  - Automatic logoff
  - Encryption/decryption

- Audit Controls (§164.312(b))
  - System activity logging
  - Access attempt monitoring
  - Data access patterns analysis

- Integrity (§164.312(c)(1))
  - Data corruption prevention
  - Authentication mechanisms
  - Encryption validation

- Transmission Security (§164.312(e)(1))
  - Encryption in transit
  - Network security controls
  - Integrity verification

## Automated Evidence Collection
The framework automatically collects evidence for:
1. **Access Management**:
   - IAM policies and permissions
   - User access patterns
   - Authentication logs

2. **Data Protection**:
   - Encryption status
   - Data integrity checks
   - Network security controls

3. **Audit Logging**:
   - System activity logs
   - Security event logs
   - Data access logs

4. **Security Controls**:
   - Vulnerability assessments
   - Network security
   - Configuration compliance

## Report Generation
The framework generates comprehensive PDF reports including:
1. **Executive Summary**:
   - Overall compliance status
   - Key metrics and findings
   - Risk assessment

2. **Control Validations**:
   - Detailed control status
   - Evidence correlation
   - Compliance gaps

3. **Technical Details**:
   - Raw evidence data
   - Validation results
   - Remediation suggestions

## Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/enhancement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/enhancement`)
5. Create a Pull Request

## License
This project is licensed under the MIT License - see the LICENSE file for details.