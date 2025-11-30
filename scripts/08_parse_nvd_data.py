from pathlib import Path
import json
import pandas as pd
from typing import Dict, List, Any, Optional, Iterable

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FINDINGS_CSV = PROJECT_ROOT / "outputs" / "nvd_summarized.csv"
OUTPUT_PARQUET = PROJECT_ROOT / "outputs" / "nvd_summarized.parquet"
PYPI_MAP = PROJECT_ROOT / "outputs" / "repo_to_pypi_map.csv"
NVD_DATA_DIR = PROJECT_ROOT / "data" / "nvd"
NVD_FILE_PATTERN = "nvdcve-*.json"


def discover_nvd_files(pattern: str = NVD_FILE_PATTERN) -> List[Path]:
    files = sorted(NVD_DATA_DIR.glob(pattern))
    if not files:
        raise FileNotFoundError(
            f"No NVD JSON files matching '{pattern}' were found in {NVD_DATA_DIR}."
        )
    return files


def parse_nvd_json(json_files: Optional[Iterable[Path]] = None) -> pd.DataFrame:
    if json_files is None:
        json_files = discover_nvd_files()

    frames: List[pd.DataFrame] = []
    total_files = 0

    for json_file_path in json_files:
        total_files += 1
        df = parse_single_nvd_file(json_file_path)
        if df.empty:
            continue
        df["source_file"] = json_file_path.name
        frames.append(df)

    if not frames:
        print("No valid NVD data parsed from the provided files.")
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.drop_duplicates(subset=["cve_id"])
    combined["cve_id"] = combined["cve_id"].astype(str).str.upper().str.strip()
    combined = combined.sort_values("cve_id").reset_index(drop=True)
    print(f"Parsed {len(combined)} unique vulnerabilities from {total_files} file(s).")
    return combined


def parse_single_nvd_file(json_file_path: Path) -> pd.DataFrame:
    try:
        with open(json_file_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        if "CVE_Items" in data:  # NVD API 1.1 format
            return parse_nvd_v1_format(data)
        elif "vulnerabilities" in data:  # NVD API 2.0 format
            return parse_nvd_v2_format(data)
        else:
            print(f"[warn] Unknown NVD JSON format in {json_file_path}")
            return pd.DataFrame()
    except FileNotFoundError:
        print(f"[warn] File not found: {json_file_path}")
        return pd.DataFrame()
    except json.JSONDecodeError as e:
        print(f"[warn] Error parsing JSON ({json_file_path}): {e}")
        return pd.DataFrame()

def parse_nvd_v1_format(data: Dict[str, Any]) -> pd.DataFrame:
    vulnerabilities = []

    for item in data['CVE_Items']:
        cve = item.get('cve', {})
        impact = item.get('impact', {})

        vuln_data = {
            'cve_id': cve.get('CVE_data_meta', {}).get('ID', ''),
            'description': get_cve_description_v1(cve),
            'published_date': item.get('publishedDate', ''),
            'last_modified': item.get('lastModifiedDate', ''),
            'cvss_v3_score': get_cvss_v3_score_v1(impact),
            'cvss_v3_severity': get_cvss_v3_severity_v1(impact),
            'cvss_v2_score': get_cvss_v2_score_v1(impact),
            'cvss_v2_severity': get_cvss_v2_severity_v1(impact),
            'cwe_ids': get_cwe_ids_v1(cve),
            'references': get_references_v1(cve),
            'cpe_names': get_cpe_names_v1(item)
        }
        vulnerabilities.append(vuln_data)

    return pd.DataFrame(vulnerabilities)

def parse_nvd_v2_format(data: Dict[str, Any]) -> pd.DataFrame:
    vulnerabilities = []

    for item in data['vulnerabilities']:
        cve = item.get('cve', {})

        vuln_data = {
            'cve_id': cve.get('id', ''),
            'description': get_cve_description_v2(cve),
            'published_date': cve.get('published', ''),
            'last_modified': cve.get('lastModified', ''),
            'cvss_v3_score': get_cvss_v3_score_v2(cve),
            'cvss_v3_severity': get_cvss_v3_severity_v2(cve),
            'cvss_v2_score': get_cvss_v2_score_v2(cve),
            'cvss_v2_severity': get_cvss_v2_severity_v2(cve),
            'cwe_ids': get_cwe_ids_v2(cve),
            'references': get_references_v2(cve),
            'cpe_names': get_cpe_names_v2(cve)
        }
        vulnerabilities.append(vuln_data)

    return pd.DataFrame(vulnerabilities)

# Helper functions for NVD v1.1 format
def get_cve_description_v1(cve: Dict[str, Any]) -> str:
    descriptions = cve.get('description', {}).get('description_data', [])
    for desc in descriptions:
        if desc.get('lang') == 'en':
            return desc.get('value', '')
    return descriptions[0].get('value', '') if descriptions else ''

def get_cvss_v3_score_v1(impact: Dict[str, Any]) -> float:
    return impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 0.0)

def get_cvss_v3_severity_v1(impact: Dict[str, Any]) -> str:
    return impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', '')

def get_cvss_v2_score_v1(impact: Dict[str, Any]) -> float:
    return impact.get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', 0.0)

def get_cvss_v2_severity_v1(impact: Dict[str, Any]) -> str:
    return impact.get('baseMetricV2', {}).get('severity', '')

def get_cwe_ids_v1(cve: Dict[str, Any]) -> str:
    cwe_ids = []
    problemtype_data = cve.get('problemtype', {}).get('problemtype_data', [])
    for problem in problemtype_data:
        for desc in problem.get('description', []):
            cwe_id = desc.get('value', '')
            if cwe_id.startswith('CWE-'):
                cwe_ids.append(cwe_id)
    return ', '.join(cwe_ids)

def get_references_v1(cve: Dict[str, Any]) -> str:
    refs = []
    ref_data = cve.get('references', {}).get('reference_data', [])
    for ref in ref_data:
        url = ref.get('url', '')
        if url:
            refs.append(url)
    return ', '.join(refs)

def get_cpe_names_v1(item: Dict[str, Any]) -> str:
    cpe_names = []
    configurations = item.get('configurations', {}).get('nodes', [])

    def extract_cpe_from_node(node):
        for cpe_match in node.get('cpe_match', []):
            cpe_name = cpe_match.get('cpe23Uri', '')
            if cpe_name:
                cpe_names.append(cpe_name)

        for child in node.get('children', []):
            extract_cpe_from_node(child)

    for config_node in configurations:
        extract_cpe_from_node(config_node)

    return ', '.join(cpe_names)

# Helper functions for NVD v2.0 format
def get_cve_description_v2(cve: Dict[str, Any]) -> str:
    descriptions = cve.get('descriptions', [])
    for desc in descriptions:
        if desc.get('lang') == 'en':
            return desc.get('value', '')
    return descriptions[0].get('value', '') if descriptions else ''

def get_cvss_v3_score_v2(cve: Dict[str, Any]) -> float:
    metrics = cve.get('metrics', {})
    for metric_type in ['cvssMetricV31', 'cvssMetricV30']:
        metric_list = metrics.get(metric_type, [])
        if metric_list:
            return metric_list[0].get('cvssData', {}).get('baseScore', 0.0)
    return 0.0

def get_cvss_v3_severity_v2(cve: Dict[str, Any]) -> str:
    metrics = cve.get('metrics', {})
    for metric_type in ['cvssMetricV31', 'cvssMetricV30']:
        metric_list = metrics.get(metric_type, [])
        if metric_list:
            return metric_list[0].get('cvssData', {}).get('baseSeverity', '')
    return ''

def get_cvss_v2_score_v2(cve: Dict[str, Any]) -> float:
    metrics = cve.get('metrics', {}).get('cvssMetricV2', [])
    if metrics:
        return metrics[0].get('cvssData', {}).get('baseScore', 0.0)
    return 0.0

def get_cvss_v2_severity_v2(cve: Dict[str, Any]) -> str:
    score = get_cvss_v2_score_v2(cve)
    if score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    elif score > 0.0:
        return 'LOW'
    return ''

def get_cwe_ids_v2(cve: Dict[str, Any]) -> str:
    cwe_ids = []
    weaknesses = cve.get('weaknesses', [])
    for weakness in weaknesses:
        for desc in weakness.get('description', []):
            cwe_id = desc.get('value', '')
            if cwe_id.startswith('CWE-'):
                cwe_ids.append(cwe_id)
    return ', '.join(cwe_ids)

def get_references_v2(cve: Dict[str, Any]) -> str:
    refs = []
    references = cve.get('references', [])
    for ref in references:
        url = ref.get('url', '')
        if url:
            refs.append(url)
    return ', '.join(refs)

def get_cpe_names_v2(cve: Dict[str, Any]) -> str:
    cpe_names = []
    configurations = cve.get('configurations', [])

    def extract_cpe_from_node(node):
        for cpe_match in node.get('cpeMatch', []):
            cpe_name = cpe_match.get('criteria', '')
            if cpe_name:
                cpe_names.append(cpe_name)

        for child in node.get('nodes', []):
            extract_cpe_from_node(child)

    for config in configurations:
        for node in config.get('nodes', []):
            extract_cpe_from_node(node)

    return ', '.join(cpe_names)

def save_to_csv_and_parquet(df: pd.DataFrame):
    if not df.empty:
        # Ensure output directory exists
        OUTPUT_PARQUET.parent.mkdir(parents=True, exist_ok=True)

        # Save to CSV
        df.to_csv(FINDINGS_CSV, index=False)
        print(f"Saved {len(df)} vulnerabilities to {FINDINGS_CSV}")

        # Save to Parquet
        df.to_parquet(OUTPUT_PARQUET, index=False)
        print(f"Saved {len(df)} vulnerabilities to {OUTPUT_PARQUET}")

        # Display basic statistics
        print(f"\nDataset summary:")
        print(f"Total vulnerabilities: {len(df)}")
        if 'cvss_v3_severity' in df.columns:
            severity_counts = df['cvss_v3_severity'].value_counts()
            print(f"CVSS v3 Severity distribution:\n{severity_counts}")
    else:
        print("No data to save")

if __name__ == "__main__":
    # Parse the NVD JSON file
    df = parse_nvd_json()

    if not df.empty:
        print(f"Parsed {len(df)} vulnerabilities from NVD JSON")
        print(f"\nColumns: {list(df.columns)}")
        print(f"\nFirst few rows:")
        print(df.head())

        # Save the results
        save_to_csv_and_parquet(df)
    else:
        print("No vulnerabilities found or file not accessible")