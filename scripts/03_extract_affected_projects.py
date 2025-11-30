import pandas as pd

df = pd.read_csv("../outputs/python_cves_cleaned.csv")

projects = df["repo_url"].drop_duplicates().sort_values()
projects.to_csv("../outputs/affected_projects.csv", index=False)

print("Saved project list to outputs/affected_projects.csv")
