#!/bin/bash

# Exit on any error
set -e

echo "Deploying HIPAA Compliance Automation to GCP..."

# Set default region if not specified
REGION=${REGION:-us-central1}

# Deploy Cloud Function
gcloud functions deploy hipaa-compliance-pipeline \
  --runtime python39 \
  --trigger-http \
  --region $REGION \
  --entry-point process_compliance \
  --memory 1024MB \
  --timeout 540s \
  --service-account hipaa-automation@$PROJECT_ID.iam.gserviceaccount.com \
  --source . \
  --env-vars-file .env.yaml \
  --security-level=secure-always

# Deploy Cloud Scheduler job
gcloud scheduler jobs create http hipaa-compliance-daily \
  --schedule "0 0 * * *" \
  --uri "https://$REGION-$PROJECT_ID.cloudfunctions.net/hipaa-compliance-pipeline" \
  --http-method POST \
  --oidc-service-account-email hipaa-automation@$PROJECT_ID.iam.gserviceaccount.com \
  --location $REGION

echo "Deployment completed successfully!"
