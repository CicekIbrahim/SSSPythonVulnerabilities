# Python CVE & Dependency Risk Study

This repository provides the full, reproducible pipeline we used to study
confirmed vulnerabilities in Python projects (Component 1) and the additional
risk surface introduced by vulnerable dependencies (Component 2). The README is
written for reviewers who need to rebuild the environment, fetch the required
data, and execute every script end-to-end.

---

## 1. Repository Layout

```
.
├── config/                   # Cross-platform settings for repo cloning & SCA
├── data/
│   ├── python_cves.csv
|   ├── repos/   
│   └── nvd/                  # Downloaded NVD CVE JSON feeds 
├── outputs/                  # Generated artifacts
├── figures/                  # Component 1 plots
├── scripts/                  # Pipeline steps 01–09
├── requirements.txt          # Python dependencies
└── README.md                 
```


---

## 2. Prerequisites & Environment Setup

- Python 3.10+ with `venv`
- Git and unzip or similar archive utility
- Internet access for cloning GitHub repositories and downloading NVD feeds
- Disk space: allow ~6 GB for cloned repos + NVD data

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

The requirements file installs `pandas`, `matplotlib`, `pip-audit`, `gitpython`,
`pyyaml`, `pyarrow`, and other utilities used across the scripts.

---

## 3. Required Inputs

### 3.1 MoreFixes slice (`data/python_cves.csv`)

1. Request access to the MoreFixes dataset (per instructions in the MoreFixes
   paper).
2. Export the Python-specific subset containing at least:
   `cve_id`, `repo_url`, `published_date`, `cvss3_base_score`,
   `cvss2_base_score`, and `problemtype_json`.
3. Save the CSV as `data/python_cves.csv`. We include this file in the repo
   because it is small and is required to start Component 1.

### 3.2 NVD JSON feeds (`data/nvd/*.json`)

The NVD feeds are too large for Git, so reviewers must download them:

1. Visit https://nvd.nist.gov/vuln/data-feeds#JSON_FEED.
2. Download every yearly archive named `nvdcve-2.0-YYYY.json.zip` covering the
   years you plan to analyze (we used the full range currently published).
3. Extract the `.json` files into `data/nvd/`. Do not rename them—script 08
   discovers every `nvdcve-*.json` automatically.

### 3.3 Directory scaffolding

- `data/repos/` — target location for cloned repositories (created automatically
  by script 05 if missing).
- `outputs/` — holds all generated CSVs, Parquet files, logs, and plots.
- `outputs/sca_raw/` — pip-audit JSON + stderr per requirements file.
- `outputs/visualizations/` — final comparison charts and narrative summary.

These folders should exist (even if empty) before running the pipeline.

---

## 4. Configuration

The file `config/sca_settings.yaml` centralizes all repository-selection and
pip-audit parameters:

- `repo_root`: where to clone candidate projects (`data/repos` by default)
?- `max_repos`: number of accepted projects to keep (default 10)
- `required_manifest_globs`: dependency files to search for
- `max_manifest_files`, `max_manifest_file_size_kb`, `max_dependency_entries`:
  thresholds used to skip unmanageable projects
- `pip_audit.timeout_seconds` and `pip_audit.skip_completed`: control scanning
  behavior
- `skip_repos`: manual list of repositories to skip
- `auto_cleanup_rejected`: removes cloned repos that failed policy checks

Adjust before script 05 if necessary

---

## 5. End-to-End Pipeline

Run each script from the repository root (`python scripts/<name>.py`). Later
steps assume the outputs of earlier scripts are present.

### Component 1 – Direct CVEs from MoreFixes

1. **Load & clean** – `scripts/01_load_and_clean.py`
   - Input: `data/python_cves.csv`
   - Output: `outputs/python_cves_cleaned.csv` (adds `year`, normalized CVSS,
     and first matched CWE)
2. **Generate charts** – `scripts/02_generate_figures.py`
   - Produces `figures/cves_by_year.png`,
     `figures/cvss_distribution.png`, `figures/top_cwes.png`
3. **Affected projects list** – `scripts/03_extract_affected_projects.py`
   - Output: `outputs/affected_projects.csv`
4. **Map to PyPI** – `scripts/04_map_to_pypi.py`
   - Output: `outputs/repo_to_pypi_map.csv`

### Component 2 – Dependency Vulnerabilities via pip-audit

5. **Clone curated repositories** – `scripts/05_clone_affected_repos.py`
   - Uses `outputs/affected_projects.csv` + `config/sca_settings.yaml`
   - Output: `outputs/cloned_repos_manifest.csv`, `outputs/clone_status.csv`,
     `outputs/auto_skip_repos.txt`, and populated `data/repos/`
6. **Run pip-audit** – `scripts/06_run_SCA.py`
   - Scans each accepted `requirements*.txt`
   - Outputs raw JSON + stderr logs to `outputs/sca_raw/`
   - Appends metadata to `outputs/sca_runs.csv`
7. **Parse SCA findings** – `scripts/07_parse_sca_results.py`
   - Produces `outputs/sca_findings.csv` and `outputs/sca_findings.parquet`
8. **Parse NVD feeds** – `scripts/08_parse_nvd_data.py`
   - Reads every `nvdcve-*.json` in `data/nvd/`
   - Outputs `outputs/nvd_summarized.parquet`
9. **Merge & analyze** – `scripts/09_analyse_sca_nvd_data.py`
   - Merges SCA findings with NVD data
   - Generates `outputs/visualizations/*.png` (year, CVSS, residual, top CWEs)
   - Writes `outputs/analysis_summary_report.txt`


---

## 6. Expected Outputs

- `figures/` – Component 1 charts
- `outputs/python_cves_cleaned.csv`
- `outputs/affected_projects.csv`
- `outputs/repo_to_pypi_map.csv`
- `outputs/cloned_repos_manifest.csv`, `outputs/clone_status.csv`,
  `outputs/auto_skip_repos.txt`
- `outputs/sca_raw/*.json` + `.stderr.log`
- `outputs/sca_runs.csv`
- `outputs/sca_findings.csv` / `outputs/sca_findings.parquet`
- `outputs/nvd_summarized.parquet`
- `outputs/visualizations/*.png`
- `outputs/analysis_summary_report.txt`


---
