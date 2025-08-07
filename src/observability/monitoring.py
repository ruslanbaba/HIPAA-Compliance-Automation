"""
Observability module for monitoring and tracing HIPAA compliance operations.
Implements OpenTelemetry for distributed tracing and metrics collection.
"""

import logging
from opentelemetry import trace, metrics
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
from opentelemetry.exporter.cloud_monitoring import CloudMonitoringMetricsExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.instrumentation.requests import RequestsInstrumentation
from google.cloud.monitoring_v3 import MetricServiceClient
import prometheus_client
from prometheus_client import Counter, Histogram, Gauge
import time

logger = logging.getLogger(__name__)

class HIPAAObservability:
    def __init__(self, config):
        self.config = config
        self.project_id = config['gcp']['project_id']
        
        # Initialize tracers and metrics
        self._setup_tracing()
        self._setup_metrics()
        self._setup_prometheus()
        
    def _setup_tracing(self):
        """Configure OpenTelemetry tracing with GCP Cloud Trace."""
        tracer_provider = TracerProvider()
        cloud_trace_exporter = CloudTraceSpanExporter(project_id=self.project_id)
        tracer_provider.add_span_processor(BatchSpanProcessor(cloud_trace_exporter))
        trace.set_tracer_provider(tracer_provider)
        
        # Instrument HTTP requests
        RequestsInstrumentation().instrument()
        
        self.tracer = trace.get_tracer(__name__)
        
    def _setup_metrics(self):
        """Configure OpenTelemetry metrics with GCP Cloud Monitoring."""
        reader = PeriodicExportingMetricReader(
            CloudMonitoringMetricsExporter(project_id=self.project_id)
        )
        meter_provider = MeterProvider(metric_readers=[reader])
        metrics.set_meter_provider(meter_provider)
        
        self.meter = metrics.get_meter(__name__)
        
    def _setup_prometheus(self):
        """Setup Prometheus metrics."""
        self.evidence_collection_duration = Histogram(
            'hipaa_evidence_collection_duration_seconds',
            'Time spent collecting HIPAA evidence',
            ['source']
        )
        
        self.compliance_status = Gauge(
            'hipaa_compliance_status',
            'Current HIPAA compliance status by control',
            ['control']
        )
        
        self.evidence_count = Counter(
            'hipaa_evidence_collected_total',
            'Total number of evidence items collected',
            ['type']
        )
        
        # Start Prometheus HTTP server
        prometheus_client.start_http_server(8000)
        
    def trace_operation(self, name):
        """Decorator for tracing operations."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                with self.tracer.start_as_current_span(name) as span:
                    try:
                        result = func(*args, **kwargs)
                        span.set_attribute("status", "success")
                        return result
                    except Exception as e:
                        span.set_attribute("status", "error")
                        span.set_attribute("error.message", str(e))
                        raise
            return wrapper
        return decorator
    
    def record_evidence_collection(self, source, duration):
        """Record evidence collection metrics."""
        self.evidence_collection_duration.labels(source=source).observe(duration)
        
    def update_compliance_status(self, control, status):
        """Update compliance status metrics."""
        self.compliance_status.labels(control=control).set(1 if status == 'compliant' else 0)
        
    def increment_evidence_count(self, evidence_type):
        """Increment evidence counter."""
        self.evidence_count.labels(type=evidence_type).inc()
        
    def create_cloud_monitoring_alert(self, control, threshold):
        """Create Cloud Monitoring alert policy."""
        client = MetricServiceClient()
        
        # Configure alert policy
        alert_policy = {
            "display_name": f"HIPAA Control {control} Alert",
            "conditions": [{
                "display_name": f"{control} non-compliance",
                "condition_threshold": {
                    "filter": f'metric.type="custom.googleapis.com/hipaa/compliance_status" AND resource.type="global" AND metric.label.control="{control}"',
                    "comparison": "COMPARISON_LT",
                    "threshold_value": threshold,
                    "duration": {"seconds": 300},  # 5 minutes
                    "trigger": {
                        "count": 1
                    }
                }
            }],
            "notification_channels": [self.config['monitoring']['notification_channel']],
            "documentation": {
                "content": f"HIPAA control {control} has fallen below compliance threshold of {threshold}",
                "mime_type": "text/markdown"
            }
        }
        
        # Create the alert policy
        try:
            response = client.create_alert_policy(
                request={"name": f"projects/{self.project_id}", "alert_policy": alert_policy}
            )
            logger.info(f"Created alert policy: {response.name}")
        except Exception as e:
            logger.error(f"Error creating alert policy: {e}")
            raise
