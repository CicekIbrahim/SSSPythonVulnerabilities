import pandas as pd
import requests
from urllib.parse import urlparse
from pathlib import Path
from tqdm import tqdm

INPUT = Path("../outputs/affected_projects.csv")
OUTPUT = Path("../outputs/repo_to_pypi_map.csv")

repos = pd.read_csv(INPUT)

def candidate_from_repo(url: str) -> str:
    """
    Take 'https://github.com/user/project' -> 'project'
    """
    path = urlparse(url).path.strip("/")
    if not path:
        return ""
    return path.split("/")[-1]

repos["candidate_name"] = repos["repo_url"].astype(str).apply(candidate_from_repo)

def lookup_pypi(name: str):
    """
    Try a few variants of the name on PyPI.
    Returns (project_name, version, repo_url_from_pypi) or (None, None, None)
    """
    if not name:
        return None, None, None

    candidates = {
        name,
        name.lower(),
        name.replace("-", "_"),
        name.replace("_", "-"),
    }

    for cand in candidates:
        try:
            r = requests.get(f"https://pypi.org/pypi/{cand}/json", timeout=10)
            if r.status_code != 200:
                continue
            js = r.json()
            info = js.get("info", {})
            proj_name = info.get("name")
            proj_version = info.get("version")

            # Try to find a repo URL in project_urls or homepage
            project_urls = info.get("project_urls") or {}
            repo_url = None
            for _, v in project_urls.items():
                if isinstance(v, str) and (
                    "github.com" in v or "gitlab.com" in v or "bitbucket.org" in v
                ):
                    repo_url = v
                    break

            if repo_url is None:
                repo_url = info.get("home_page")

            return proj_name, proj_version, repo_url
        except Exception:
            continue

    return None, None, None

rows = []
for _, row in tqdm(repos.iterrows(), total=len(repos)):
    repo_url = row["repo_url"]
    candidate = row["candidate_name"]
    p_name, p_ver, p_repo = lookup_pypi(candidate)

    def norm(u: str) -> str:
        if not isinstance(u, str):
            return ""
        u = u.strip().lower()
        if u.endswith(".git"):
            u = u[:-4]
        return u.rstrip("/")

    match = norm(repo_url) and norm(p_repo) and norm(repo_url) == norm(p_repo)

    rows.append(
        {
            "repo_url": repo_url,
            "candidate_name": candidate,
            "pypi_name": p_name,
            "pypi_version": p_ver,
            "pypi_repo_url": p_repo,
            "pypi_match": bool(match),
        }
    )

out = pd.DataFrame(rows)
out.to_csv(OUTPUT, index=False)
print("Saved PyPI mapping to:", OUTPUT)
print("Total repos:", len(out))
print("Repos with confirmed PyPI match:", out["pypi_match"].sum())
