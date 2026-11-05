# Contributing to the GCP Sensitive Data Protection (SDP) Governance Benchmark

Thank you for your interest in contributing to the **GCP Sensitive Data Protection (SDP) Governance Benchmark**. Because this repository models sensitive data detection, privacy engineering, and financial compliance workflows, all contributions must strictly adhere to our security sanitization and reproducibility standards.

---

## 1. Security Sanitization & Hygiene Rules (Mandatory)

Before opening a Pull Request, verify that your changes satisfy every requirement below:

1. **Zero Real PII or Credentials:**
   * Never commit real names, residential addresses, phone numbers, email addresses, Social Security Numbers, credit card numbers, or live API keys.
   * All test credit card numbers must be synthetically generated Luhn-valid test ranges (e.g., standard test prefixes `411111...` or `550000...`).
2. **Deterministic Synthetic Seeds:**
   * All data generators must initialize deterministic random seeds (`Faker.seed(42)` and `random.seed(42)`) so benchmark metrics remain 100% reproducible across environments and CI runs.
3. **RFC 2606 Reserved Domains Only:**
   * Never use real corporate domains in sample payloads, email addresses, or URLs.
   * Strictly use IETF RFC 2606 reserved top-level domains and second-level domains:
     * `example.com`
     * `example.org`
     * `example.net`
     * `*.internal.test`
4. **No Internal URLs or Project Identifiers:**
   * Do not reference internal corporate hostnames, private issue trackers, or real GCP project IDs.
   * Always parameterize project identifiers (`your-gcp-project-id`) and resolve defaults dynamically via `gcloud config get-value project`.
5. **Notebook Output Hygiene:**
   * If committing executed Jupyter notebook outputs, ensure all cell outputs derive exclusively from the deterministic `Faker.seed(42)` dataset and contain zero real cloud project credentials or service account keys.

---

## 2. Development Workflow

1. **Fork & Branch:**
   Create a feature branch from `main` using a descriptive prefix (`feat/`, `fix/`, `docs/`).
2. **Virtual Environment:**
   Always use an isolated virtual environment (`.venv`) and install dependencies from `requirements.txt`:
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```
3. **Idempotent Shell Scripts:**
   Any modifications to `scripts/deploy_test_stores.sh` or other shell scripts must include `set -euo pipefail` and use conditional creation flags (such as `--if_not_exists`) to guarantee idempotent execution.
4. **Notebook Formatting:**
   Every code cell in `notebooks/sdp_detection_and_governance_benchmark.ipynb` must be preceded by a clear Markdown section explaining the architectural purpose and governance logic of the step, and configurable cells should preserve Google Colab `# @param` annotations.

---

## 3. Licensing

By contributing to this repository, you agree that your contributions will be licensed under the [Apache License, Version 2.0](LICENSE).
