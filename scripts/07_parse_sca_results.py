import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUN_LOG = PROJECT_ROOT / "outputs" / "sca_runs.csv"
OUTPUT_CSV = PROJECT_ROOT / "outputs" / "sca_findings.csv"
OUTPUT_PARQUET = PROJECT_ROOT / "outputs" / "sca_findings.parquet"
PYPI_MAP = PROJECT_ROOT / "outputs" / "repo_to_pypi_map.csv"


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_TO_SCORE = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 3.0,
    "UNKNOWN": 0.0,
}


def load_run_log() -> pd.DataFrame:
    if not RUN_LOG.exists():
        raise FileNotFoundError(f"Run log not found: {RUN_LOG}")
    return pd.read_csv(RUN_LOG)


def load_pypi_map() -> Dict[str, str]:
    if not PYPI_MAP.exists():
        return {}
    df = pd.read_csv(PYPI_MAP)
    df["repo_url"] = df["repo_url"].astype(str)
    df["pypi_name"] = df["pypi_name"].fillna("")
    return dict(zip(df["repo_url"], df["pypi_name"]))


def parse_raw_files(run_log: pd.DataFrame, pypi_map: Dict[str, str]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []

    for _, row in run_log.iterrows():
        output_file = Path(row["output_file"])
        if not output_file.exists():
            continue

        repo_url = row.get("repo_url")
        requirements_file = row.get("requirements_file")
        tool_version = row.get("pip_audit_version")
        timestamp = row.get("timestamp_utc")
        parsed_timestamp = parse_timestamp(timestamp)

        with output_file.open("r", encoding="utf-8") as handle:
            raw_text = handle.read().strip()
        if not raw_text:
            continue

        try:
            parsed_json = json.loads(raw_text)
        except json.JSONDecodeError:
            continue

        dependencies = extract_dependencies(parsed_json)
        if not dependencies:
            continue

        for entry in dependencies:
            package = entry.get("name")
            version = entry.get("version")
            vulnerabilities = entry.get("vulns") or []

            for vuln in vulnerabilities:
                aliases = vuln.get("aliases") or []
                cve_id = extract_cve_id(aliases)
                cvss_score, cvss_vector = extract_cvss(vuln)
                cwes = vuln.get("cwes") or []
                references = vuln.get("references") or []
                severity_text = (vuln.get("severity") or "").upper().strip()

                records.append(
                    {
                        "repo_url": repo_url,
                        "pypi_name": pypi_map.get(repo_url, ""),
                        "requirements_file": requirements_file,
                        "package": package,
                        "installed_version": version,
                        "advisory_id": vuln.get("id"),
                        "cve_id": cve_id,
                        "aliases": "; ".join(aliases),
                        "severity": severity_text,
                        "fix_versions": "; ".join(vuln.get("fix_versions") or []),
                        "description": vuln.get("description"),
                        "cwe": "; ".join(cwes),
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "severity_rank": severity_rank(severity_text),
                        "severity_numeric": SEVERITY_TO_SCORE.get(severity_text, None),
                        "references": "; ".join(references),
                        "tool_version": tool_version,
                        "scan_timestamp": parsed_timestamp,
                        "status": row.get("status"),
                        "return_code": row.get("return_code"),
                    }
                )

    return records
def extract_cve_id(aliases: List[str]) -> str:
    for alias in aliases:
        if isinstance(alias, str) and alias.upper().startswith("CVE-"):
            return alias.upper()
    return ""


def extract_dependencies(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        dependencies = data.get("dependencies")
        if isinstance(dependencies, list):
            return dependencies
    return []


def extract_cvss(vuln: Dict[str, Any]) -> tuple[Any, Any]:
    cvss_data = vuln.get("cvss")
    if isinstance(cvss_data, list) and cvss_data:
        first = cvss_data[0]
        return first.get("score"), first.get("vector")
    if isinstance(cvss_data, dict):
        return cvss_data.get("score"), cvss_data.get("vector")
    return None, None


def severity_rank(severity: str) -> int:
    if severity in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(severity)
    return len(SEVERITY_ORDER)



def parse_timestamp(timestamp_str: str) -> str:
    if not timestamp_str:
        return ""
    try:
        return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return timestamp_str


def main() -> None:
    run_log = load_run_log()
    pypi_map = load_pypi_map()
    records = parse_raw_files(run_log, pypi_map)

    columns = [
        "repo_url",
        "pypi_name",
        "requirements_file",
        "package",
        "installed_version",
        "advisory_id",
        "cve_id",
        "aliases",
        "severity",
        "severity_rank",
        "severity_numeric",
        "fix_versions",
        "description",
        "cwe",
        "cvss_score",
        "cvss_vector",
        "references",
        "tool_version",
        "scan_timestamp",
        "status",
        "return_code",
    ]

    df = pd.DataFrame(records, columns=columns)
    df.to_csv(OUTPUT_CSV, index=False)
    df.to_parquet(OUTPUT_PARQUET, index=False)

    print(
        f"Parsed {len(df)} findings from {len(run_log)} scan entries. "
        f"Saved to {OUTPUT_CSV} and {OUTPUT_PARQUET}."
    )


if __name__ == "__main__":
    main()

