import csv
import os
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import yaml
from git import Repo
from git.exc import GitCommandError, InvalidGitRepositoryError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "sca_settings.yaml"
AFFECTED_PROJECTS = PROJECT_ROOT / "outputs" / "affected_projects.csv"
MANIFEST_PATH = PROJECT_ROOT / "outputs" / "cloned_repos_manifest.csv"
STATUS_LOG_PATH = PROJECT_ROOT / "outputs" / "clone_status.csv"
AUTO_SKIP_LOG_PATH = PROJECT_ROOT / "outputs" / "auto_skip_repos.txt"

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
}


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"Missing config file: {CONFIG_PATH}")
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def resolve_path(path_str: str) -> Path:
    path = Path(path_str)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def should_ignore(path: Path) -> bool:
    return any(part in IGNORED_DIRS for part in path.parts)


def discover_manifest_files(repo_path: Path, patterns: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for pattern in patterns:
        for candidate in repo_path.rglob(pattern):
            if not candidate.is_file():
                continue
            if should_ignore(candidate):
                continue
            files.append(candidate)
    # remove duplicates and sort for stability
    unique = sorted({file.resolve() for file in files})
    return unique


def evaluate_manifests(
    manifests: list[Path],
    max_manifest_files: int | None,
    max_manifest_file_size_kb: int | None,
    max_dependency_entries: int | None,
) -> tuple[str, str]:
    if not manifests:
        return "missing_manifests", "No dependency files matching criteria."

    if max_manifest_files and len(manifests) > max_manifest_files:
        return (
            "too_many_manifests",
            f"{len(manifests)} files exceed threshold ({max_manifest_files}).",
        )

    if max_manifest_file_size_kb:
        largest_file = max(manifests, key=lambda p: p.stat().st_size)
        largest_kb = largest_file.stat().st_size / 1024
        if largest_kb > max_manifest_file_size_kb:
            return (
                "manifest_too_large",
                f"{largest_file.name} is {largest_kb:.0f} KB "
                f"(limit {max_manifest_file_size_kb} KB).",
            )

    if max_dependency_entries:
        for manifest in manifests:
            entries = estimate_dependency_entries(manifest)
            if entries is None:
                continue
            if entries > max_dependency_entries:
                return (
                    "manifest_too_complex",
                    f"{manifest.name} has {entries} entries "
                    f"(limit {max_dependency_entries}).",
                )

    return "accepted", ""


def estimate_dependency_entries(path: Path) -> int | None:
    try:
        count = 0
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.lower().startswith(("-r ", "--requirement")):
                    continue
                if stripped.startswith("-") and "index-url" in stripped:
                    continue
                count += 1
        return count
    except (OSError, UnicodeDecodeError):
        return None


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def clone_repositories() -> None:
    cfg = load_config()
    repo_root = resolve_path(cfg.get("repo_root", "data/repos"))
    repo_root.mkdir(parents=True, exist_ok=True)

    manifest_globs = cfg.get("required_manifest_globs") or ["requirements*.txt"]
    max_manifest_files = cfg.get("max_manifest_files")
    max_manifest_files = int(max_manifest_files) if max_manifest_files else None
    max_manifest_file_size_kb = cfg.get("max_manifest_file_size_kb")
    max_manifest_file_size_kb = (
        int(max_manifest_file_size_kb) if max_manifest_file_size_kb else None
    )
    max_dependency_entries = cfg.get("max_dependency_entries")
    max_dependency_entries = (
        int(max_dependency_entries) if max_dependency_entries else None
    )

    max_repos = cfg.get("max_repos")
    max_repos = int(max_repos) if max_repos not in (None, "") else None

    manual_skip = {repo.lower().strip() for repo in cfg.get("skip_repos", [])}
    auto_skip_existing = read_auto_skip_file()
    skip_repos = manual_skip | set(auto_skip_existing.keys())
    auto_cleanup_rejected = bool(cfg.get("auto_cleanup_rejected", False))
    auto_skip_new: dict[str, str] = {}

    if auto_cleanup_rejected:
        cleanup_auto_skipped_repos(auto_skip_existing, repo_root)

    with AFFECTED_PROJECTS.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        projects = list(reader)

    if not projects:
        print("No repositories found in affected_projects.csv")
        return

    manifest_rows: list[dict] = []
    status_rows: list[dict] = []
    accepted_count = 0

    for row in projects:
        if max_repos and accepted_count >= max_repos:
            break

        repo_url = (row.get("repo_url") or "").strip()
        if not repo_url.startswith("https://github.com/"):
            continue

        if repo_url.lower() in skip_repos:
            print(f"[skip-config] {repo_url} marked to skip.")
            continue

        repo_name = repo_url.rstrip("/").split("/")[-1]
        destination = repo_root / repo_name

        try:
            if destination.exists():
                repo = Repo(destination)
                print(f"[reuse] {repo_url} already cloned.")
            else:
                print(f"[clone] {repo_url} -> {destination}")
                repo = Repo.clone_from(repo_url, destination)
        except (GitCommandError, InvalidGitRepositoryError) as exc:
            reason = f"clone_failed: {exc}"
            status_rows.append(
                {
                    "repo_url": repo_url,
                    "local_path": str(destination),
                    "status": "clone_failed",
                    "reason": reason,
                    "manifest_count": 0,
                    "manifest_paths": "",
                    "commit": "",
                    "timestamp_utc": timestamp(),
                }
            )
            print(f"[error] Failed to clone {repo_url}: {exc}")
            continue

        manifests = discover_manifest_files(destination, manifest_globs)
        status, reason = evaluate_manifests(
            manifests,
            max_manifest_files,
            max_manifest_file_size_kb,
            max_dependency_entries,
        )
        manifest_paths = ";".join(str(path) for path in manifests)

        status_rows.append(
            {
                "repo_url": repo_url,
                "local_path": str(destination),
                "status": status,
                "reason": reason,
                "manifest_count": len(manifests),
                "manifest_paths": manifest_paths,
                "commit": repo.head.commit.hexsha,
                "timestamp_utc": timestamp(),
            }
        )

        if status != "accepted":
            print(f"[skip] {repo_url} -> {status} ({reason})")
            if auto_cleanup_rejected and destination.exists():
                try:
                    cleanup_path(destination)
                except PermissionError as exc:
                    print(
                        f"[warn] cleanup failed for {destination}: {exc}. "
                        "Remove manually if needed."
                    )
            auto_skip_new[repo_url.lower()] = str(destination)
            continue

        manifest_rows.append(
            {
                "repo_url": repo_url,
                "local_path": str(destination),
                "commit": repo.head.commit.hexsha,
                "default_branch": repo.active_branch.name
                if not repo.head.is_detached
                else "",
                "manifest_count": len(manifests),
                "manifest_paths": manifest_paths,
            }
        )

        accepted_count += 1

    write_manifest(manifest_rows)
    merged_auto_skip = {**auto_skip_existing, **auto_skip_new}
    write_status_log(status_rows, auto_skip_new.keys())
    update_auto_skip_log(merged_auto_skip)

    if max_repos:
        print(
            f"Selected {accepted_count}/{max_repos} repositories "
            "with acceptable dependency manifests."
        )
    else:
        print(f"Selected {accepted_count} repositories with acceptable dependency manifests.")


def write_manifest(rows: list[dict]) -> None:
    if not rows:
        print("No eligible repositories to record in manifest.")
        MANIFEST_PATH.unlink(missing_ok=True)
        return

    fieldnames = [
        "repo_url",
        "local_path",
        "commit",
        "default_branch",
        "manifest_count",
        "manifest_paths",
    ]
    with MANIFEST_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote manifest for {len(rows)} repos to {MANIFEST_PATH}")


def write_status_log(rows: list[dict], auto_skipped: Iterable[str]) -> None:
    if not rows:
        STATUS_LOG_PATH.unlink(missing_ok=True)
        return

    fieldnames = [
        "repo_url",
        "local_path",
        "status",
        "reason",
        "manifest_count",
        "manifest_paths",
        "commit",
        "timestamp_utc",
    ]
    with STATUS_LOG_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote clone status log to {STATUS_LOG_PATH}")
    for repo in auto_skipped:
        print(f"[auto-skip] {repo}")


def update_auto_skip_log(auto_skipped: dict[str, str]) -> None:
    if not auto_skipped:
        if AUTO_SKIP_LOG_PATH.exists():
            AUTO_SKIP_LOG_PATH.unlink()
        return

    with AUTO_SKIP_LOG_PATH.open("w", encoding="utf-8") as handle:
        for repo_url in sorted(auto_skipped.keys()):
            local_path = auto_skipped.get(repo_url, "")
            handle.write(f"{repo_url},{local_path}\n")


def read_auto_skip_file() -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not AUTO_SKIP_LOG_PATH.exists():
        return mapping

    for line in AUTO_SKIP_LOG_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        if "," in line:
            repo_url, local_path = line.split(",", 1)
            mapping[repo_url.strip().lower()] = local_path.strip()
        else:
            mapping[line.strip().lower()] = ""
    return mapping


def cleanup_auto_skipped_repos(auto_skipped: dict[str, str], repo_root: Path) -> None:
    if not auto_skipped:
        return
    for repo_url_lower, recorded_path in auto_skipped.items():
        candidate_path = Path(recorded_path) if recorded_path else None
        if not candidate_path or not candidate_path.exists():
            repo_name = repo_url_lower.rstrip("/").split("/")[-1]
            candidate_path = repo_root / repo_name
        if candidate_path.exists():
            try:
                cleanup_path(candidate_path)
                print(f"[auto-clean] Removed leftover {candidate_path}")
            except PermissionError as exc:
                print(
                    f"[warn] auto-clean failed for {candidate_path}: {exc}. "
                    "Remove manually if needed."
                )


def cleanup_path(path: Path) -> None:
    if not path.exists():
        return

    def handle_remove_readonly(func, target_path, exc_info):
        exc_type, exc_value, _ = exc_info
        if isinstance(exc_value, PermissionError):
            try:
                os.chmod(target_path, stat.S_IWRITE)
            except PermissionError:
                pass
            func(target_path)
        else:
            raise exc_value

    if path.is_file():
        path.unlink(missing_ok=True)
        return

    try:
        shutil.rmtree(path, onerror=handle_remove_readonly)
    except PermissionError:
        force_remove_with_command(path)


def force_remove_with_command(path: Path) -> None:
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "rmdir", "/s", "/q", str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        subprocess.run(
            ["rm", "-rf", str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


if __name__ == "__main__":
    clone_repositories()
