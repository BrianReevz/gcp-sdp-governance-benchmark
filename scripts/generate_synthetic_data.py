#!/usr/bin/env python3
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

"""Deterministic synthetic data generator for GCP Sensitive Data Protection (SDP) benchmarking.

Generates 1,000+ structured records (JSONL and CSV) plus unstructured customer support logs
with exact statistical distributions covering:
  - 70% Baseline clean records (City/State/ZIP only, no street address, benign identifiers)
  - 10% Address proximity violations (Street Address Line 1 + City/State/ZIP)
  -  5% Single-column address blobs (Full residential address embedded in a single column)
  -  5% Numeric disambiguation cases (16-digit unformatted ledger currency vs. Luhn-valid Visa/MC PANs)
  -  5% High-entropy API tokens with Bearer hotwords vs. clean UUIDs and Git commit SHAs
  -  5% Sparse fields (95% null across dataset; populated 5% contains names, P2P wallet handles,
        Merchant Account IDs, phone numbers, and RFC 2606 email addresses)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pathlib
import random
import string
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from faker import Faker

# Enforce deterministic generation for reproducible benchmarks
SEED = 42
Faker.seed(SEED)
random.seed(SEED)

RFC2606_DOMAINS = ("example.com", "example.org", "example.net", "internal.test")


def generate_luhn_pan(prefix: str, length: int = 16) -> str:
    """Generates a deterministic, Luhn-valid synthetic test PAN (Visa/Mastercard)."""
    body_len = length - len(prefix) - 1
    body = "".join(random.choices(string.digits, k=body_len))
    partial = prefix + body

    # Calculate Luhn check digit
    digits = [int(d) for d in partial]
    checksum = 0
    for idx, digit in enumerate(reversed(digits)):
        if idx % 2 == 0:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    check_digit = (10 - (checksum % 10)) % 10
    return f"{partial}{check_digit}"


def generate_non_luhn_16_digit_currency() -> str:
    """Generates a 16-digit unformatted ledger micro-currency string guaranteed to fail Luhn."""
    # Example: 1000000000250000 ($10,000,000.00250000 in scaled ledger integer units)
    base = f"100000{random.randint(100000000, 999999999)}"
    # Ensure last digit breaks Luhn check so SDP Luhn validation distinguishes it from PANs
    digits = [int(d) for d in base]
    checksum = 0
    for idx, digit in enumerate(reversed(digits)):
        if idx % 2 == 0:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    valid_check = (10 - (checksum % 10)) % 10
    invalid_check = (valid_check + 1) % 10
    return f"{base}{invalid_check}"


def generate_merchant_account_id() -> str:
    """Generates a custom Merchant Account ID matching `ACCT-[0-9A-Z]{10}`."""
    chars = string.ascii_uppercase + string.digits
    return "ACCT-" + "".join(random.choices(chars, k=10))


def generate_p2p_wallet_handle(fake: Faker) -> str:
    """Generates a custom P2P wallet handle matching `@[A-Za-z0-9_-]{3,30}`."""
    first = fake.first_name().lower()
    last = fake.last_name().lower()
    suffix = random.randint(10, 999)
    sep = random.choice(["-", "_"])
    return f"@{first}{sep}{last}{suffix}"[:30]


def generate_live_secret_token() -> str:
    """Generates a synthetic high-entropy credential matching `tok_synth_[a-f0-9]{16,64}`."""
    hex_chars = "0123456789abcdef"
    token_body = "".join(random.choices(hex_chars, k=32))
    return f"tok_synth_{token_body}"


def generate_git_sha(seed_str: str) -> str:
    """Generates a deterministic 40-char Git commit SHA."""
    return hashlib.sha1(seed_str.encode("utf-8")).hexdigest()


def build_synthetic_dataset(num_records: int = 1200) -> list[dict[str, Any]]:
    """Builds the structured dataset matching exact benchmark cohort percentages."""
    fake = Faker("en_US")
    Faker.seed(SEED)
    random.seed(SEED)

    # Calculate exact cohort boundaries:
    # 70% baseline_clean
    # 10% address_proximity_violation
    #  5% single_column_address_blob
    #  5% numeric_disambiguation
    #  5% high_entropy_credential
    #  5% sparse_field_pii
    n_baseline = int(num_records * 0.70)
    n_addr_prox = int(num_records * 0.10)
    n_addr_blob = int(num_records * 0.05)
    n_disambig = int(num_records * 0.05)
    n_entropy = int(num_records * 0.05)
    n_sparse = num_records - (
        n_baseline + n_addr_prox + n_addr_blob + n_disambig + n_entropy
    )

    cohorts = (
        ["BASELINE_CLEAN"] * n_baseline
        + ["ADDRESS_PROXIMITY_VIOLATION"] * n_addr_prox
        + ["SINGLE_COLUMN_ADDRESS_BLOB"] * n_addr_blob
        + ["NUMERIC_DISAMBIGUATION"] * n_disambig
        + ["HIGH_ENTROPY_CREDENTIAL"] * n_entropy
        + ["SPARSE_FIELD_PII"] * n_sparse
    )
    random.shuffle(cohorts)

    base_ts = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    records: list[dict[str, Any]] = []

    for idx, cohort in enumerate(cohorts, start=1):
        # Column 1: customer_id (Downstream SHA-256 hashed / pseudonymous key - EXEMPT)
        raw_cust_id = f"CUST-{idx:08d}"
        hashed_cust_id = (
            f"CUST-{idx:08d}-"
            f"{hashlib.sha256(raw_cust_id.encode('utf-8')).hexdigest()[:12]}"
        )

        city = fake.city()
        state = fake.state_abbr()
        zipcode = fake.zipcode()
        tx_uuid = str(uuid.UUID(int=random.getrandbits(128), version=4))
        git_sha = generate_git_sha(f"commit-{idx}")

        # Default clean values across columns
        street_line_1: str | None = None
        full_address_blob: str | None = (
            f"{city}, {state} {zipcode}"  # Benign City/State/ZIP only by default
        )
        payment_reference: str = (
            f"usd_ledger_formatted=${random.randint(10, 5000)}.{random.randint(0, 99):02d}"
        )
        auth_diagnostic_header: str = (
            f"correlation_id={tx_uuid} release_sha={git_sha}"
        )
        # 95% null sparse field across dataset (only populated in SPARSE_FIELD_PII cohort)
        sparse_support_notes: str | None = None
        expected_contains_pii: bool = False

        if cohort == "BASELINE_CLEAN":
            # 70%: Clean City/State/ZIP only, no street address, no secrets, null sparse field
            expected_contains_pii = False

        elif cohort == "ADDRESS_PROXIMITY_VIOLATION":
            # 10%: Street Line 1 populated alongside City/State/ZIP
            street_line_1 = fake.street_address()
            full_address_blob = f"{street_line_1}, {city}, {state} {zipcode}"
            expected_contains_pii = True

        elif cohort == "SINGLE_COLUMN_ADDRESS_BLOB":
            # 5%: Single-column unstructured residential address blob
            street = fake.street_address()
            apt = f"Apt {random.randint(1, 999)}"
            full_address_blob = (
                f"SHIP_TO_RESIDENTIAL: {street} {apt}, {city}, {state} {zipcode}"
            )
            expected_contains_pii = True

        elif cohort == "NUMERIC_DISAMBIGUATION":
            # 5%: Half 16-digit unformatted currency (benign), half Visa/MC test PANs (PII)
            if idx % 2 == 0:
                pan_prefix = random.choice(["411111", "550000", "424242"])
                pan = generate_luhn_pan(pan_prefix, 16)
                payment_reference = f"card_pan_captured={pan} (settlement_retry)"
                expected_contains_pii = True
            else:
                raw_currency = generate_non_luhn_16_digit_currency()
                payment_reference = (
                    f"usd_ledger_raw={raw_currency} minor_units FX_RATE_SCALED"
                )
                expected_contains_pii = False

        elif cohort == "HIGH_ENTROPY_CREDENTIAL":
            # 5%: Half live API tokens with Bearer hotwords (sensitive), half benign UUID/Git SHA
            if idx % 2 == 0:
                secret_token = generate_live_secret_token()
                auth_diagnostic_header = (
                    f"Authorization: Bearer {secret_token} (api_key_debug_dump)"
                )
                expected_contains_pii = True
            else:
                auth_diagnostic_header = (
                    f"trace_uuid={tx_uuid} git_sha={git_sha} status=VERIFIED_CLEAN"
                )
                expected_contains_pii = False

        elif cohort == "SPARSE_FIELD_PII":
            # 5%: Populated sparse notes containing customer name, P2P wallet handle, Merchant Account ID, phone, email, or SSN
            cust_name = fake.name()
            wallet_handle = generate_p2p_wallet_handle(fake)
            merchant_acct_id = generate_merchant_account_id()
            phone = f"+1-{random.randint(201, 989)}-{random.randint(200, 999)}-{random.randint(1000, 9999)}"
            domain = random.choice(RFC2606_DOMAINS)
            email = f"{cust_name.lower().replace(' ', '.')}@{domain}"
            ssn_snippet = (
                f"ssn={random.randint(100, 899)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
                if idx % 3 == 0
                else ""
            )
            sparse_support_notes = (
                f"Agent escalation for {cust_name} ({email}): linked merchant account {merchant_acct_id} "
                f"and P2P wallet handle {wallet_handle}. Callback number {phone}. {ssn_snippet}".strip()
            )
            expected_contains_pii = True

        record_ts = (base_ts + timedelta(seconds=idx * 37)).isoformat()
        records.append(
            {
                "customer_id": hashed_cust_id,
                "event_timestamp": record_ts,
                "benchmark_cohort": cohort,
                "expected_contains_pii": expected_contains_pii,
                "street_line_1": street_line_1,
                "city": city,
                "state": state,
                "postal_code": zipcode,
                "full_address_blob": full_address_blob,
                "payment_reference": payment_reference,
                "auth_diagnostic_header": auth_diagnostic_header,
                "sparse_support_notes": sparse_support_notes,
            }
        )

    return records


def build_support_interaction_logs(
    records: list[dict[str, Any]], num_logs: int = 180
) -> list[str]:
    """Generates unstructured customer support interaction log lines simulating GCS log files."""
    fake = Faker("en_US")
    Faker.seed(SEED + 1)
    random.seed(SEED + 1)

    log_lines: list[str] = []
    base_ts = datetime(2026, 2, 1, 8, 0, 0, tzinfo=timezone.utc)

    for i in range(num_logs):
        ts = (base_ts + timedelta(minutes=i * 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        session_id = f"SUP-{100000 + i}"
        sample_rec = records[i % len(records)]
        cust_id = sample_rec["customer_id"]

        scenario = i % 6
        if scenario == 0:
            # Benign city/state/zip + Git SHA log
            line = (
                f"{ts} [INFO] [{session_id}] customer_id={cust_id} "
                f"msg=\"Customer inquired about regional availability in {sample_rec['city']}, "
                f"{sample_rec['state']} {sample_rec['postal_code']}. Build git_sha={generate_git_sha(session_id)}\""
            )
        elif scenario == 1:
            # Unstructured log with Merchant Account ID, P2P wallet handle, and RFC 2606 email
            acct_id = generate_merchant_account_id()
            wallet_handle = generate_p2p_wallet_handle(fake)
            email = f"user.{i}@example.com"
            line = (
                f"{ts} [WARN] [{session_id}] customer_id={cust_id} "
                f"msg=\"Account linking failure for payer_id={acct_id} with P2P wallet handle {wallet_handle} "
                f"and contact email {email}\""
            )
        elif scenario == 2:
            # Unstructured log leaking live bearer credential
            secret = generate_live_secret_token()
            line = (
                f"{ts} [ERROR] [{session_id}] customer_id={cust_id} "
                f"msg=\"Webhook retry failed with header Authorization: Bearer {secret} "
                f"target=https://webhook.internal.test/v1/events\""
            )
        elif scenario == 3:
            # Unstructured log with Luhn-valid test credit card and residential street address
            pan = generate_luhn_pan("411111", 16)
            street = fake.street_address()
            line = (
                f"{ts} [ALERT] [{session_id}] customer_id={cust_id} "
                f"msg=\"Unmasked chat transcript: please charge card {pan} billing address "
                f"{street}, {sample_rec['city']}, {sample_rec['state']} {sample_rec['postal_code']}\""
            )
        elif scenario == 4:
            # Unstructured log with 16-digit unformatted ledger currency (false-positive test)
            raw_curr = generate_non_luhn_16_digit_currency()
            line = (
                f"{ts} [INFO] [{session_id}] customer_id={cust_id} "
                f"msg=\"Settlement batch reconciled: usd_ledger_raw={raw_curr} minor_units FX_RATE=1.0000\""
            )
        else:
            # Unstructured log with US SSN and phone number
            ssn = f"{random.randint(100, 899)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
            phone = f"+1-415-555-{random.randint(1000, 9999)}"
            line = (
                f"{ts} [WARN] [{session_id}] customer_id={cust_id} "
                f"msg=\"KYC manual verification note: tax_id ssn={ssn} verified via callback {phone}\""
            )
        log_lines.append(line)

    return log_lines


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate deterministic synthetic data for GCP SDP benchmarking."
    )
    parser.add_argument(
        "--num-records",
        type=int,
        default=1200,
        help="Total number of structured synthetic records to generate (default: 1200).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/samples",
        help="Output directory for generated sample files (default: data/samples).",
    )
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    out_dir = repo_root / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    records = build_synthetic_dataset(num_records=args.num_records)
    log_lines = build_support_interaction_logs(records=records, num_logs=180)

    jsonl_path = out_dir / "synthetic_records.jsonl"
    csv_path = out_dir / "synthetic_records.csv"
    log_path = out_dir / "customer_support_interactions.log"

    # Write JSONL for BigQuery load and GCS structured storage
    with jsonl_path.open("w", encoding="utf-8") as f_jsonl:
        for row in records:
            f_jsonl.write(json.dumps(row) + "\n")

    # Write CSV for quick local inspection
    if records:
        fieldnames = list(records[0].keys())
        with csv_path.open("w", encoding="utf-8", newline="") as f_csv:
            writer = csv.DictWriter(f_csv, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)

    # Write unstructured customer support logs
    with log_path.open("w", encoding="utf-8") as f_log:
        for line in log_lines:
            f_log.write(line + "\n")

    # Summarize cohort distribution and null sparsity
    cohort_counts: dict[str, int] = {}
    null_sparse_count = 0
    for r in records:
        cohort = r["benchmark_cohort"]
        cohort_counts[cohort] = cohort_counts.get(cohort, 0) + 1
        if r["sparse_support_notes"] is None:
            null_sparse_count += 1

    print("=" * 72)
    print("GCP SDP Governance Benchmark - Synthetic Data Generation Complete")
    print("=" * 72)
    print(f"Total Structured Records : {len(records):,}")
    print(f"Unstructured Log Lines   : {len(log_lines):,}")
    print(
        f"Sparse Column Null Rate  : {(null_sparse_count / len(records)) * 100:.1f}% "
        f"({null_sparse_count:,}/{len(records):,} nulls in sparse_support_notes)"
    )
    print("-" * 72)
    print("Cohort Breakdown:")
    for cohort_name, count in sorted(cohort_counts.items()):
        pct = (count / len(records)) * 100
        print(f"  - {cohort_name:<30} : {count:>5} rows ({pct:>5.1f}%)")
    print("-" * 72)
    print(f"JSONL Output : {jsonl_path}")
    print(f"CSV Output   : {csv_path}")
    print(f"Log Output   : {log_path}")
    print("=" * 72)


if __name__ == "__main__":
    main()
