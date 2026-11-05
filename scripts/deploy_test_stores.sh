#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Idempotent provisioning script for the GCP SDP Governance Benchmark.
# Generates deterministic synthetic data, creates the BigQuery dataset/table,
# and provisions the Cloud Storage (GCS) bucket with uniform bucket-level access.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Resolve GCP Project ID and Region
PROJECT_ID="${PROJECT_ID:-$(CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity" gcloud config get-value project 2>/dev/null || true)}"
if [[ -z "${PROJECT_ID}" || "${PROJECT_ID}" == "(unset)" ]]; then
  echo "ERROR: No active GCP project found. Set PROJECT_ID or run 'gcloud config set project YOUR_PROJECT_ID'." >&2
  exit 1
fi

REGION="${REGION:-us-central1}"
BQ_DATASET="${BQ_DATASET:-fintech_sdp_benchmark}"
BQ_TABLE="${BQ_TABLE:-customer_transactions_synthetic}"
GCS_BUCKET="gs://${PROJECT_ID}-sdp-benchmark-samples"

echo "========================================================================"
echo "Deploying GCP SDP Governance Benchmark Test Stores"
echo "------------------------------------------------------------------------"
echo "Project ID : ${PROJECT_ID}"
echo "Region     : ${REGION}"
echo "BQ Dataset : ${PROJECT_ID}:${BQ_DATASET}.${BQ_TABLE}"
echo "GCS Bucket : ${GCS_BUCKET}"
echo "========================================================================"

# 1. Invoke synthetic data generator
PYTHON_BIN="python3"
if [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
fi

echo "[1/4] Generating deterministic synthetic records and unstructured support logs..."
"${PYTHON_BIN}" "${REPO_ROOT}/scripts/generate_synthetic_data.py"

JSONL_FILE="${REPO_ROOT}/data/samples/synthetic_records.jsonl"
LOG_FILE="${REPO_ROOT}/data/samples/customer_support_interactions.log"

# 2. Create BigQuery dataset (idempotent via --force / conditional check)
echo "[2/4] Ensuring BigQuery dataset '${BQ_DATASET}' exists in ${REGION}..."
if ! bq --project_id="${PROJECT_ID}" show --dataset "${PROJECT_ID}:${BQ_DATASET}" >/dev/null 2>&1; then
  bq --location="${REGION}" --project_id="${PROJECT_ID}" mk \
    --dataset \
    --force \
    --label datacloud:antigravity \
    --description="Synthetic benchmark dataset for GCP Sensitive Data Protection (SDP) governance evaluation" \
    "${PROJECT_ID}:${BQ_DATASET}"
else
  echo "Dataset ${PROJECT_ID}:${BQ_DATASET} already exists."
fi

# 3. Load newline-delimited JSON into BigQuery
echo "[3/4] Loading structured JSONL records into '${PROJECT_ID}:${BQ_DATASET}.${BQ_TABLE}'..."
bq --location="${REGION}" --project_id="${PROJECT_ID}" load \
  --replace \
  --source_format=NEWLINE_DELIMITED_JSON \
  --label datacloud:antigravity \
  "${PROJECT_ID}:${BQ_DATASET}.${BQ_TABLE}" \
  "${JSONL_FILE}" \
  "customer_id:STRING,event_timestamp:TIMESTAMP,benchmark_cohort:STRING,expected_contains_pii:BOOLEAN,street_line_1:STRING,city:STRING,state:STRING,postal_code:STRING,full_address_blob:STRING,payment_reference:STRING,auth_diagnostic_header:STRING,sparse_support_notes:STRING"

# 4. Provision GCS Bucket with Uniform Bucket-Level Access and upload files
echo "[4/4] Provisioning GCS bucket '${GCS_BUCKET}' with uniform bucket-level access..."
if ! CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity" \
  gcloud storage buckets describe "${GCS_BUCKET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity" \
    gcloud storage buckets create "${GCS_BUCKET}" \
    --project="${PROJECT_ID}" \
    --location="${REGION}" \
    --uniform-bucket-level-access \
    --public-access-prevention
else
  echo "Bucket ${GCS_BUCKET} already exists; ensuring uniform bucket-level access is enabled..."
  CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity" \
    gcloud storage buckets update "${GCS_BUCKET}" \
    --project="${PROJECT_ID}" \
    --uniform-bucket-level-access
fi

echo "Uploading structured JSONL and unstructured support logs to '${GCS_BUCKET}'..."
CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity" \
  gcloud storage cp "${JSONL_FILE}" "${GCS_BUCKET}/structured/synthetic_records.jsonl" --project="${PROJECT_ID}"
CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity" \
  gcloud storage cp "${LOG_FILE}" "${GCS_BUCKET}/logs/customer_support_interactions.log" --project="${PROJECT_ID}"

echo "========================================================================"
echo "Deployment complete!"
echo "  - BigQuery Table : ${PROJECT_ID}.${BQ_DATASET}.${BQ_TABLE}"
echo "  - GCS JSONL      : ${GCS_BUCKET}/structured/synthetic_records.jsonl"
echo "  - GCS Logs       : ${GCS_BUCKET}/logs/customer_support_interactions.log"
echo "========================================================================"
