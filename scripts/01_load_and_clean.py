import pandas as pd
import ast
import re
from pathlib import Path

# Input / Output paths
INPUT = Path("../data/python_cves.csv")
CLEANED = Path("../outputs/python_cves_cleaned.csv")

df = pd.read_csv(INPUT)

# --- Extract year ---
df["year"] = pd.to_datetime(df["published_date"], errors="coerce").dt.year

# --- Normalize CVSS ---
df["cvss_score"] = (
    pd.to_numeric(df["cvss3_base_score"], errors="coerce")
    .fillna(pd.to_numeric(df["cvss2_base_score"], errors="coerce"))
)

# --- Extract CWE from JSON ---
def extract_cwe(raw):
    try:
        if pd.isna(raw):
            return None
        # Use ast.literal_eval since the data is stored as Python dict string
        data = ast.literal_eval(raw)
        # Look for CWE numbers (CWE-XXX format) in the description values
        cwe_pattern = re.compile(r'CWE-\d+')
        for entry in data:
            for desc in entry.get("description", []):
                value = desc.get("value", "")
                match = cwe_pattern.search(value)
                if match:
                    return match.group(0)
    except:
        return None

df["cwe"] = df["problemtype_json"].apply(extract_cwe)

# Save cleaned version
df.to_csv(CLEANED, index=False)
print("Saved cleaned CSV to:", CLEANED)
print("Rows:", len(df))
