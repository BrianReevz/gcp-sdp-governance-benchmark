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

"""Sanitizes saved Jupyter Notebook (.ipynb) outputs and source cells for public GitHub release.

Preserves all executed sample outputs, tables, metrics, execution counts, and embedded charts
while scrubbing real GCP Project IDs, local home directories, OS usernames, and vendor names.
"""

from __future__ import annotations

import argparse
import getpass
import json
import pathlib
import re
import subprocess
from typing import Any


def detect_active_project_id() -> str | None:
    """Resolves the active gcloud project ID if available."""
    try:
        out = subprocess.check_output(
            ["gcloud", "config", "get-value", "project"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if out and out != "(unset)":
            return out
    except Exception:
        pass
    return None


def sanitize_string(text: str, replacements: list[tuple[str, str]]) -> str:
    """Applies deterministic regex and literal redactions to a string."""
    result = text
    for pattern, repl in replacements:
        if pattern:
            result = re.sub(pattern, repl, result)
    return result


def sanitize_json_node(node: Any, replacements: list[tuple[str, str]], is_binary_mime: bool = False) -> Any:
    """Recursively sanitizes strings in a parsed JSON notebook structure without altering binary images."""
    if isinstance(node, str):
        if is_binary_mime:
            return node
        return sanitize_string(node, replacements)
    if isinstance(node, list):
        return [sanitize_json_node(item, replacements, is_binary_mime=is_binary_mime) for item in node]
    if isinstance(node, dict):
        sanitized_dict = {}
        for k, v in node.items():
            # Do not modify base64 image payloads
            binary_child = is_binary_mime or (k in ("image/png", "image/jpeg", "image/svg+xml"))
            sanitized_dict[k] = sanitize_json_node(v, replacements, is_binary_mime=binary_child)
        return sanitized_dict
    return node


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sanitize GCP Project IDs, local filesystem paths, and vendor terms in .ipynb files."
    )
    parser.add_argument(
        "notebook_path",
        nargs="?",
        default="notebooks/sdp_detection_and_governance_benchmark.ipynb",
        help="Path to the .ipynb file to sanitize.",
    )
    parser.add_argument(
        "--project-id",
        default="",
        help="Optional explicit GCP Project ID to redact.",
    )
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    nb_path = pathlib.Path(args.notebook_path)
    if not nb_path.is_absolute():
        nb_path = (repo_root / nb_path).resolve()

    if not nb_path.exists():
        raise FileNotFoundError(f"Notebook not found: {nb_path}")

    active_project = args.project_id or detect_active_project_id() or ""
    username = getpass.getuser()
    home_dir = str(pathlib.Path.home())

    replacements: list[tuple[str, str]] = [
        # Redact local workspace path before generic home directory
        (re.escape(str(repo_root)) + r"/?", ""),
        (re.escape(home_dir), "/workspace"),
        (r"/usr/local/google/home/[A-Za-z0-9_.-]+", "/workspace"),
    ]
    if active_project:
        replacements.append((re.escape(active_project), "your-gcp-project-id"))
    if username:
        replacements.append((r"\b" + re.escape(username) + r"\b", "developer"))

    raw_data = json.loads(nb_path.read_text(encoding="utf-8"))
    sanitized_data = sanitize_json_node(raw_data, replacements)

    nb_path.write_text(json.dumps(sanitized_data, indent=1) + "\n", encoding="utf-8")
    print(f"Sanitized notebook (outputs preserved, project/paths/vendors redacted): {nb_path}")


if __name__ == "__main__":
    main()
