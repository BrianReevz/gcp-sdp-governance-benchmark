## 3. Detailed File Implementation Requirements

### File 1: `README.md`
* **Style & Format:** High-polish open-source documentation adhering to Google Cloud Architecture Center style. Use standard [shields.io](https://shields.io/) badges (Python, GCP, License: Apache 2.0).
* **Sections:**
  1. Title, Badges, and Architecture Overview diagram (ASCII or Mermaid.js).
  2. The Enterprise Challenge: Balancing Zero-Risk Tolerance with False-Positive Fatigue.
  3. Detection Taxonomy & Proximity Rules (Markdown comparison table).
  4. Repository Structure & Quickstart Guide (Prerequisites, environment setup, execution commands).
  5. Empirical Likelihood Tuning: Precision vs. Recall Governance Trade-offs.
  6. Compliance & Audits (PCI-DSS Level 1, FedRAMP High, SOC 2).
  7. Open Source Sanitization & Disclaimers (No confidential internal links, generic placeholders only).

---

### File 2: `requirements.txt`
Include pinned, compatible versions:
* `google-cloud-dlp>=3.18.0`
* `google-cloud-bigquery>=3.20.0`
* `google-cloud-storage>=2.16.0`
* `pandas>=2.2.0`
* `pyarrow>=15.0.0`
* `tabulate>=0.9.0`
* `faker>=24.0.0`

---

### File 3: `scripts/generate_synthetic_data.py`
* Standalone Python script utilizing `Faker` with a fixed seed (`Faker.seed(42)`).
* Generates 1,000+ realistic synthetic records representing all edge cases:
  * **70%** Baseline clean records (City/State/Zip only).
  * **10%** Address proximity violations (Street Line 1 + City/State/Zip).
  * **5%** Single-column address blobs.
  * **5%** Disambiguation test cases (16-digit unformatted currency vs. Visa/Mastercard test PANs).
  * **5%** High-entropy API tokens with bearer hotwords vs. clean UUIDs and Git SHAs.
  * **5%** Sparse fields (95% null, populated notes containing customer names, P2P wallet handles, and phone numbers).
* Generates an unstructured text log file (`customer_support_interactions.log`) simulating GCS customer support logs.
* Outputs files to `data/samples/`.

---

### File 4: `scripts/deploy_test_stores.sh`
* Executable Bash script configured with `set -euo pipefail`.
* Automatically resolves the GCP Project ID via `gcloud config get-value project` and supports `REGION` override (default: `us-central1`).
* Invokes `generate_synthetic_data.py`.
* Creates a BigQuery dataset (`fintech_sdp_benchmark`) and loads the newline-delimited JSON data using `bq load`.
* Provisions a GCS bucket (`gs://${PROJECT_ID}-sdp-benchmark-samples`) with uniform bucket-level access and uploads the unstructured support logs and structured JSONL.

---

### File 5: `notebooks/sdp_detection_and_governance_benchmark.ipynb`
Colab-compatible Jupyter notebook with rich Markdown headings and documentation before every cell.

#### Cell Workflow:
1. **Dependencies & Authentication:**
   * Automatic detection of Google Colab environment (`google.colab.auth.authenticate_user()`) with fallback to Application Default Credentials (ADC).
2. **Configurable Parameters:**
   * Interactive `@param` fields for `PROJECT_ID`, `REGION`, `BQ_DATASET`, `BQ_TABLE`, `GCS_BUCKET`, and `SAMPLE_PERCENT` (10%–20%).
3. **Data Ingestion & Sampling:**
   * BigQuery query utilizing `TABLESAMPLE SYSTEM (20 PERCENT)` to evaluate efficiency on subsets.
   * Ingestion of GCS unstructured support logs.
   * Column null-percentage profiler to optimize scanning on sparse fields.
4. **SDP Inspection Configuration:**
   * **Built-in infoTypes:** `CREDIT_CARD_NUMBER`, `US_SOCIAL_SECURITY_NUMBER`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `STREET_ADDRESS`.
   * **Custom regex infoTypes:**
     * Merchant Account ID: `ACCT-[0-9A-Z]{10}`
     * P2P Wallet Handle: `@[A-Za-z0-9_-]{3,30}`
     * High-Entropy Credential: `tok_synth_[a-f0-9]{16,64}`
   * Proximity rule evaluation logic (differentiating standalone City/State/ZIP from Street Address Line 1/2).
5. **Column-Aware Execution:**
   * Loop scanning DataFrame columns while tagging Column 1 (`customer_id`) as `EXEMPT_HASHED_DOWNSTREAM`.
   * Performance timing metrics (total duration, rows/second inspected).
6. **Model Governance Summary Matrix:**
   * Aggregates findings by minimum Likelihood tier (`VERY_UNLIKELY` to `VERY_LIKELY`).
   * Outputs a scannable Markdown table showing actionable vs. exempted findings to demonstrate false-positive reduction.
7. **Triage Export & De-Identification Demonstration:**
   * Exports actionable flagged records to `manual_audit_triage_queue.csv`.
   * Demonstrates SDP `deidentify_content` with surrogate masking (`[REDACTED_PII]`) on sample text.

---

### File 6: `CONTRIBUTING.md` & `LICENSE`
* Standard Apache 2.0 License.
* Contribution guidelines covering security sanitization: no internal URLs, no real PII, deterministic synthetic seeds.

---

## 4. Output Deliverables
Generate all file contents in full, ready to be committed to GitHub. Ensure all code is syntactically valid, self-contained, and thoroughly commented.

---

### 🚀 Recommended Public Repository Standards

When publishing this repository to an open-source organization, apply the following design and formatting conventions:

| Standard Category | Recommended Practice | Purpose & Impact |
| :--- | :--- | :--- |
| **Visual Hierarchy** | Use GitHub-flavored Markdown badges, bold section callouts, and clean Markdown tables (`\|---\|`). | Improves scannability for enterprise review boards and auditors. |
| **Parameterization** | Implement Google Colab form fields (`# @param {type:"string"}`) in all setup cells. | Enables non-technical auditors to adjust project IDs and sampling rates without editing code. |
| **Sanitization & Hygiene** | Use `Faker.seed(42)` and replace all corporate domains with RFC 2606 reserved domains (`example.com`, `internal.test`). | Eliminates privacy leakage and ensures reproducible benchmark runs. |
| **Idempotent Automation** | Shell scripts must use `set -euo pipefail` and conditional creation flags (`--if_not_exists`). | Prevents script crashes during repeated testing or CI/CD deployments. |