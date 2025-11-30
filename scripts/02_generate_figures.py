import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

df = pd.read_csv("../outputs/python_cves_cleaned.csv")
fig_dir = Path("../figures")
fig_dir.mkdir(exist_ok=True)

# --- CVEs per year ---
df["year"].value_counts().sort_index().plot(kind="bar", figsize=(8,4), title="Python CVEs by Year")
plt.tight_layout()
plt.savefig(fig_dir / "cves_by_year.png")
plt.close()

# --- CVSS distribution ---
df["cvss_score"].dropna().plot(kind="hist", bins=20, figsize=(8,4), title="CVSS Score Distribution")
plt.xlabel("CVSS Score")
plt.tight_layout()
plt.savefig(fig_dir / "cvss_distribution.png")
plt.close()

# --- Top CWEs ---
cwe_counts = df["cwe"].dropna().value_counts().head(15)
if len(cwe_counts) > 0:
    cwe_counts.plot(kind="barh", figsize=(8,6), title="Top Python CWE Types")
    plt.tight_layout()
    plt.savefig(fig_dir / "top_cwes.png")
    plt.close()
else:
    print("Warning: No CWE data available to plot")

print("Figures saved in figures/")
