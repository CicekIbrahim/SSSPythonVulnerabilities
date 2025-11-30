import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import re
import numpy as np
from datetime import datetime

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCA_FINDINGS_CSV = PROJECT_ROOT / "outputs" / "sca_findings.csv"
NVD_FINDINGS_CSV = PROJECT_ROOT / "outputs" / "nvd_summarized.csv"
OUTPUT_DIR = PROJECT_ROOT / "outputs" / "visualizations"

# Ensure output directory exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def load_data():
    """Load SCA findings and NVD data."""
    try:
        sca_df = pd.read_csv(SCA_FINDINGS_CSV)
        print(f"Loaded {len(sca_df)} SCA findings")
    except FileNotFoundError:
        print(f"SCA findings file not found: {SCA_FINDINGS_CSV}")
        sca_df = pd.DataFrame()

    try:
        nvd_df = pd.read_csv(NVD_FINDINGS_CSV)
        print(f"Loaded {len(nvd_df)} NVD records")
    except FileNotFoundError:
        print(f"NVD findings file not found: {NVD_FINDINGS_CSV}")
        nvd_df = pd.DataFrame()

    return sca_df, nvd_df

def extract_cve_year(cve_id):
    """Extract year from CVE ID (format: CVE-YYYY-NNNNN)."""
    if pd.isna(cve_id) or not isinstance(cve_id, str):
        return None

    match = re.match(r'CVE-(\d{4})-\d+', cve_id)
    if match:
        return int(match.group(1))
    return None

def merge_sca_nvd_data(sca_df, nvd_df):
    """Merge SCA findings with NVD data based on CVE IDs."""
    if sca_df.empty or nvd_df.empty:
        print("Cannot merge: one or both datasets are empty")
        return pd.DataFrame()

    # Ensure CVE IDs are properly formatted and not null
    sca_df_clean = sca_df.dropna(subset=['cve_id']).copy()
    nvd_df_clean = nvd_df.dropna(subset=['cve_id']).copy()

    rename_map = {
        "severity": "severity_sca",
        "severity_rank": "severity_rank_sca",
        "severity_numeric": "severity_numeric_sca",
        "cvss_score": "cvss_score_sca",
        "cvss_vector": "cvss_vector_sca",
    }
    sca_df_clean = sca_df_clean.rename(columns=rename_map)

    # Merge on CVE ID
    merged_df = pd.merge(
        sca_df_clean,
        nvd_df_clean,
        on='cve_id',
        how='inner',
        suffixes=('_sca', '_nvd')
    )

    print(f"Successfully merged {len(merged_df)} records")
    return merged_df

def visualize_cve_year_distribution(df, source_name=""):
    """Create visualization for CVE year distribution."""
    df = df.copy()
    df["cve_year"] = df["cve_id"].apply(extract_cve_year)
    df_with_years = df.dropna(subset=["cve_year"])

    if df_with_years.empty:
        print(f"No valid CVE years found in {source_name}")
        return

    years = df_with_years["cve_year"].astype(int)
    year_counts = years.value_counts().sort_index()

    fig, axes = plt.subplots(2, 1, figsize=(12, 10))

    axes[0].hist(years, bins=range(int(years.min()), int(years.max()) + 2),
                 alpha=0.7, color="skyblue", edgecolor="black")
    axes[0].set_xlabel("CVE Year")
    axes[0].set_ylabel("Number of CVEs")
    axes[0].set_title(f"Distribution of CVE Years {source_name}")
    axes[0].grid(True, alpha=0.3)

    axes[1].plot(year_counts.index, year_counts.values,
                 marker="o", linewidth=2, markersize=6)
    axes[1].set_xlabel("Year")
    axes[1].set_ylabel("Number of CVEs")
    axes[1].set_title(f"CVE Trend Over Time {source_name}")
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()

    filename = f"cve_year_distribution_{clean_name(source_name)}.png"
    plt.savefig(OUTPUT_DIR / filename, dpi=300, bbox_inches="tight")
    print(f"Saved CVE year distribution plot: {filename}")
    plt.close(fig)

    print(f"\nCVE Year Statistics {source_name}:")
    print(f"Total CVEs: {len(df_with_years)}")
    print(f"Year range: {years.min()} - {years.max()}")
    print(f"Most common year: {year_counts.idxmax()} ({year_counts.max()} CVEs)")


def clean_name(text: str) -> str:
    return text.lower().replace(" ", "_").replace("(", "").replace(")", "")


def visualize_cvss_scores(df, source_name=""):
    """Create visualization for CVSS scores distribution."""
    cvss_columns = [
        col for col in df.columns
        if "cvss" in col.lower() and "score" in col.lower()
    ]
    if "severity_numeric" in df.columns:
        cvss_columns.append("severity_numeric")

    valid_columns = []
    for col in cvss_columns:
        scores = pd.to_numeric(df[col], errors="coerce").dropna()
        if not scores.empty:
            valid_columns.append((col, scores))

    if not valid_columns:
        print(f"No usable CVSS score columns found in {source_name}")
        return

    n_cols = len(valid_columns)
    fig, axes = plt.subplots(2, n_cols, figsize=(6 * n_cols, 8))
    if n_cols == 1:
        axes = axes.reshape(2, 1)

    for i, (col, scores) in enumerate(valid_columns):
        axes[0, i].hist(scores, bins=20, alpha=0.7, color="lightcoral",
                        edgecolor="black")
        axes[0, i].set_xlabel("CVSS Score")
        axes[0, i].set_ylabel("Frequency")
        axes[0, i].set_title(f"{col} Distribution {source_name}")
        axes[0, i].grid(True, alpha=0.3)

        axes[1, i].boxplot(scores)
        axes[1, i].set_ylabel("CVSS Score")
        axes[1, i].set_title(f"{col} Box Plot {source_name}")
        axes[1, i].grid(True, alpha=0.3)

        print(f"\n{col} Statistics {source_name}:")
        print(f"  Count: {len(scores)}")
        print(f"  Mean: {scores.mean():.2f}")
        print(f"  Median: {scores.median():.2f}")
        print(f"  Std: {scores.std():.2f}")
        print(f"  Range: {scores.min():.1f} - {scores.max():.1f}")

    plt.tight_layout()
    filename = f"cvss_scores_distribution_{clean_name(source_name)}.png"
    plt.savefig(OUTPUT_DIR / filename, dpi=300, bbox_inches="tight")
    print(f"Saved CVSS scores distribution plot: {filename}")
    plt.close(fig)


def visualize_severity_distribution(df, source_name=""):
    severity_columns = [
        col for col in df.columns if "severity" in col.lower()
    ]

    valid = []
    for col in severity_columns:
        counts = df[col].dropna()
        if counts.empty:
            continue
        valid.append((col, counts))

    if not valid:
        print(f"No severity columns with data found in {source_name}")
        return

    fig, axes = plt.subplots(1, len(valid), figsize=(6 * len(valid), 6))
    if len(valid) == 1:
        axes = [axes]

    for ax, (col, counts) in zip(axes, valid):
        series = counts.value_counts()
        ax.pie(series.values, labels=series.index, autopct="%1.1f%%",
               startangle=90)
        ax.set_title(f"{col} Distribution {source_name}")

    plt.tight_layout()
    filename = f"severity_distribution_{clean_name(source_name)}.png"
    plt.savefig(OUTPUT_DIR / filename, dpi=300, bbox_inches="tight")
    print(f"Saved severity distribution plot: {filename}")
    plt.close(fig)

def create_comparison_visualizations(sca_df, nvd_df, merged_df):
    """Create comparison visualizations between SCA and NVD data."""
    if merged_df.empty:
        print("Cannot create comparison visualizations: no merged data")
        return

    # Compare CVSS scores if available in both datasets
    sca_metric, sca_label = select_sca_metric(merged_df)
    nvd_metric, nvd_label = select_nvd_metric(merged_df, nvd_df)

    if sca_metric is None or nvd_metric is None:
        print("Skipping CVSS comparison plot: metric missing.")
        return

    fig, axes = plt.subplots(1, 2, figsize=(15, 6))

    common_idx = sca_metric.index.intersection(nvd_metric.index)
    if len(common_idx) > 0:
        axes[0].scatter(sca_metric[common_idx], nvd_metric[common_idx], alpha=0.6, color="steelblue")
        axes[0].plot([0, 10], [0, 10], "r--", label="Perfect Agreement")
        axes[0].set_xlabel(f"SCA {sca_label}")
        axes[0].set_ylabel(f"NVD {nvd_label}")
        axes[0].set_title("SCA vs NVD Severity Comparison")
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)
    else:
        axes[0].text(0.5, 0.5, "No overlapping scores", ha="center", va="center")
        axes[0].set_axis_off()

    axes[1].hist(
        [sca_metric.dropna(), nvd_metric.dropna()],
        bins=20,
        alpha=0.7,
        label=["SCA", "NVD"],
        color=["blue", "red"],
    )
    axes[1].set_xlabel("Score")
    axes[1].set_ylabel("Frequency")
    axes[1].set_title("Severity Distribution Comparison")
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "sca_nvd_cvss_comparison.png", dpi=300, bbox_inches="tight")
    print("Saved SCA vs NVD severity comparison plot")
    plt.close(fig)

    # Residual plot (NVD - SCA)
    if len(common_idx) > 0:
        residuals = nvd_metric[common_idx] - sca_metric[common_idx]
        fig_res, ax_res = plt.subplots(figsize=(10, 4))
        ax_res.axhline(0, color="gray", linestyle="--", linewidth=1)
        ax_res.bar(range(len(residuals)), residuals, color="mediumpurple", alpha=0.8)
        ax_res.set_xlabel("Matched CVE index")
        ax_res.set_ylabel(f"{nvd_label} - {sca_label}")
        ax_res.set_title("Severity Residuals (NVD minus SCA)")
        ax_res.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "sca_nvd_severity_residuals.png", dpi=300, bbox_inches="tight")
        print("Saved severity residual plot.")
        plt.close(fig_res)

    visualize_cwe_distribution(merged_df, source_name="Dependencies (Merged)")


def select_sca_metric(merged_df):
    preferred = [
        "severity_numeric_sca",
        "cvss_score_sca",
    ]
    preferred.extend(
        col for col in merged_df.columns
        if col not in preferred and col.endswith("_sca") and "cvss" in col.lower() and "score" in col.lower()
    )
    preferred.extend(
        col for col in merged_df.columns
        if col not in preferred and "cvss" in col.lower() and "score" in col.lower()
    )

    for col in preferred:
        scores = pd.to_numeric(merged_df.get(col), errors="coerce").dropna()
        if not scores.empty:
            return scores, col
    return None, None


def select_nvd_metric(merged_df, nvd_df):
    priority = ["cvss_v3_score", "cvss_v2_score"]
    priority.extend(
        col for col in nvd_df.columns
        if col not in priority and 'cvss' in col.lower() and 'score' in col.lower()
    )

    for col in priority:
        if col in merged_df.columns:
            scores = pd.to_numeric(merged_df[col], errors="coerce").dropna()
            if not scores.empty:
                return scores, col
    return None, None


def visualize_cwe_distribution(df, source_name=""):
    cwe_columns = [col for col in ["cwe", "cwe_ids"] if col in df.columns]
    if not cwe_columns:
        return

    cwe_series = None
    for col in cwe_columns:
        series = df[col].dropna()
        if not series.empty:
            cwe_series = series
            break
    if cwe_series is None or cwe_series.empty:
        return

    exploded = (
        cwe_series.astype(str)
        .str.split(";")
        .explode()
        .str.strip()
        .replace("", None)
        .dropna()
    )
    if exploded.empty:
        return

    top_cwes = exploded.value_counts().head(5)

    fig, ax = plt.subplots(figsize=(8, 4))
    top_cwes.plot(kind="barh", ax=ax, color="teal")
    ax.set_xlabel("Count")
    ax.set_ylabel("CWE")
    ax.set_title(f"Top CWE Categories {source_name}")
    ax.invert_yaxis()
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "dependency_top_cwes.png", dpi=300, bbox_inches="tight")
    print("Saved dependency CWE distribution plot.")
    plt.close(fig)

def generate_summary_report(sca_df, nvd_df, merged_df):
    """Generate a summary report of the analysis."""
    report = []
    report.append("=" * 60)
    report.append("SCA-NVD DATA ANALYSIS SUMMARY REPORT")
    report.append("=" * 60)
    report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")

    # Dataset statistics
    report.append("DATASET STATISTICS:")
    report.append("-" * 20)
    report.append(f"SCA Findings: {len(sca_df)} records")
    report.append(f"NVD Records: {len(nvd_df)} records")
    report.append(f"Merged Records: {len(merged_df)} records")
    if not sca_df.empty and not merged_df.empty:
        coverage = (len(merged_df) / len(sca_df)) * 100
        report.append(f"NVD Coverage: {coverage:.1f}% of SCA findings")
    report.append("")

    # CVE year analysis
    if not merged_df.empty:
        merged_df['cve_year'] = merged_df['cve_id'].apply(extract_cve_year)
        years = merged_df['cve_year'].dropna()
        if not years.empty:
            report.append("CVE YEAR ANALYSIS:")
            report.append("-" * 18)
            report.append(f"Year Range: {years.min():.0f} - {years.max():.0f}")
            report.append(f"Most Common Year: {years.mode().iloc[0]:.0f}")
            report.append(f"Average Year: {years.mean():.1f}")
            report.append("")

    # CVSS analysis
    cvss_cols = [col for col in merged_df.columns if 'cvss' in col.lower() and 'score' in col.lower()]
    if "severity_numeric" in merged_df.columns:
        cvss_cols.append("severity_numeric")
    if cvss_cols:
        report.append("CVSS SCORE ANALYSIS:")
        report.append("-" * 19)
        for col in cvss_cols:
            scores = pd.to_numeric(merged_df[col], errors='coerce').dropna()
            if not scores.empty:
                report.append(f"{col}:")
                report.append(f"  Mean: {scores.mean():.2f}")
                report.append(f"  Median: {scores.median():.2f}")
                report.append(f"  High Risk (>7.0): {(scores > 7.0).sum()} ({(scores > 7.0).mean()*100:.1f}%)")
                report.append("")

    # Save report
    report_text = "\n".join(report)
    report_file = OUTPUT_DIR / "analysis_summary_report.txt"
    with open(report_file, 'w') as f:
        f.write(report_text)

    print(report_text)
    print(f"\nSaved summary report: {report_file}")

def main():
    """Main function to run the analysis."""
    print("Loading data...")
    sca_df, nvd_df = load_data()

    if sca_df.empty and nvd_df.empty:
        print("No data available for analysis")
        return

    # Merge datasets
    merged_df = merge_sca_nvd_data(sca_df, nvd_df)

    # Create visualizations for individual datasets
    # if not sca_df.empty:
    #     print("\n" + "="*50)
    #     print("ANALYZING SCA FINDINGS")
    #     print("="*50)
    #     visualize_cve_year_distribution(sca_df, "(SCA)")
    #     # visualize_cvss_scores(sca_df, "(SCA)")
    #     # visualize_severity_distribution(sca_df, "(SCA)")
    #
    # if not nvd_df.empty:
    #     print("\n" + "="*50)
    #     print("ANALYZING NVD DATA")
    #     print("="*50)
    #     visualize_cve_year_distribution(nvd_df, "(NVD)")
    #     visualize_cvss_scores(nvd_df, "(NVD)")
    #     visualize_severity_distribution(nvd_df, "(NVD)")

    # Create comparison visualizations
    if not merged_df.empty:
        print("\n" + "="*50)
        print("CREATING COMPARISON VISUALIZATIONS")
        print("="*50)
        visualize_cve_year_distribution(merged_df, "(Merged)")
        visualize_cvss_scores(merged_df, "(Merged)")
        create_comparison_visualizations(sca_df, nvd_df, merged_df)

    # Generate summary report
    print("\n" + "="*50)
    print("GENERATING SUMMARY REPORT")
    print("="*50)
    generate_summary_report(sca_df, nvd_df, merged_df)

    print(f"\nAll visualizations saved to: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()