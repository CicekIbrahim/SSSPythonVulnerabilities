import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "sca_settings.yaml"
MANIFEST_PATH = PROJECT_ROOT / "outputs" / "cloned_repos_manifest.csv"
RAW_OUTPUT_DIR = PROJECT_ROOT / "outputs" / "sca_raw"
RUN_LOG = PROJECT_ROOT / "outputs" / "sca_runs.csv"

IGNORED_DIRS = {".git", ".hg", ".svn", ".tox", ".venv", "venv", "__pycache__"}


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"Missing config file: {CONFIG_PATH}")
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def ensure_manifest_exists() -> list[dict]:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(
            "Manifest not found. Run scripts/05_clone_affected_repos.py first."
        )
    with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return list(reader)


def get_pip_audit_version() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "pip_audit", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def should_ignore(path: Path) -> bool:
    return any(part in IGNORED_DIRS for part in path.parts)


def discover_requirement_files(repo_path: Path) -> list[Path]:
    requirement_files = []
    for req_file in repo_path.rglob("requirements*.txt"):
        if not req_file.is_file():
            continue
        if should_ignore(req_file):
            continue
        requirement_files.append(req_file)
    return requirement_files


def run_pip_audit(
    requirements_file: Path,
    output_file: Path,
    extra_args: list[str],
    timeout_seconds: int | float | None = None,
) -> tuple[int, str, str]:
    cmd = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(requirements_file),
        "--format",
        "json",
        "--desc",
    ]
    cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=requirements_file.parent,
            timeout=timeout_seconds,
        )
        stdout, stderr = result.stdout, result.stderr
        return_code = result.returncode
        status = "success" if return_code == 0 else "error"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + "\n[pip-audit] Timed out."
        return_code = -1
        status = "timeout"

    output_file.write_text(stdout, encoding="utf-8")
    stderr_path = output_file.with_suffix(".stderr.log")
    stderr_path.write_text(stderr or "", encoding="utf-8")

    return return_code, stdout, status


def sanitize_filename(path: Path, repo_path: Path) -> str:
    relative = path.relative_to(repo_path)
    slug = "__".join(relative.parts)
    return slug.replace(" ", "_")


def main() -> None:
    cfg = load_config()
    manifest_rows = ensure_manifest_exists()
    RAW_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    tool_version = get_pip_audit_version()
    pip_audit_cfg = cfg.get("pip_audit", {}) or {}
    extra_args = pip_audit_cfg.get("extra_args") or []
    timeout_seconds = pip_audit_cfg.get("timeout_seconds")
    skip_completed = bool(pip_audit_cfg.get("skip_completed", False))

    run_records = []

    for row in manifest_rows:
        repo_url = row.get("repo_url", "")
        local_path = Path(row.get("local_path", "")).expanduser()
        if not local_path.exists():
            print(f"[warn] Local path missing for {repo_url}: {local_path}")
            continue

        manifest_paths = [
            Path(path_str)
            for path_str in (row.get("manifest_paths") or "").split(";")
            if path_str
        ]

        requirement_files = (
            manifest_paths
            if manifest_paths
            else discover_requirement_files(local_path)
        )
        if not requirement_files:
            print(f"[info] No requirements*.txt files found in {local_path}")
            continue

        for req_file in requirement_files:
            output_name = sanitize_filename(req_file, local_path)
            output_file = RAW_OUTPUT_DIR / f"{local_path.name}__{output_name}.json"

            if skip_completed and output_file.exists():
                print(f"[skip] Existing results for {req_file}")
                run_records.append(
                    {
                        "repo_url": repo_url,
                        "local_path": str(local_path),
                        "requirements_file": str(req_file),
                        "output_file": str(output_file),
                        "pip_audit_version": tool_version,
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "return_code": "",
                        "status": "skipped",
                        "finding_count": "",
                    }
                )
                continue

            print(f"[audit] {repo_url} ({req_file})")
            return_code, stdout, raw_status = run_pip_audit(
                req_file, output_file, extra_args, timeout_seconds
            )
            timestamp = datetime.now(timezone.utc).isoformat()
            finding_count = count_findings(stdout)

            if raw_status == "error" and return_code == 1 and finding_count > 0:
                status = "findings"
            else:
                status = raw_status

            run_records.append(
                {
                    "repo_url": repo_url,
                    "local_path": str(local_path),
                    "requirements_file": str(req_file),
                    "output_file": str(output_file),
                    "pip_audit_version": tool_version,
                    "timestamp_utc": timestamp,
                    "return_code": return_code,
                    "status": status,
                    "finding_count": finding_count,
                }
            )

    append_run_log(run_records)


def append_run_log(records: list[dict]) -> None:
    if not records:
        print("No SCA runs executed.")
        return

    fieldnames = [
        "repo_url",
        "local_path",
        "requirements_file",
        "output_file",
        "pip_audit_version",
        "timestamp_utc",
        "return_code",
        "status",
        "finding_count",
    ]

    log_exists = RUN_LOG.exists()
    with RUN_LOG.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if not log_exists:
            writer.writeheader()
        writer.writerows(records)

    print(f"Logged {len(records)} entries to {RUN_LOG}")


def count_findings(raw_json: str) -> int:
    if not raw_json.strip():
        return 0
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return 0
    if isinstance(data, list):
        return sum(len(entry.get("vulns", [])) for entry in data)
    if isinstance(data, dict):
        dependencies = data.get("dependencies") or []
        return sum(len(dep.get("vulns", [])) for dep in dependencies)
    return 0


if __name__ == "__main__":
    main()
