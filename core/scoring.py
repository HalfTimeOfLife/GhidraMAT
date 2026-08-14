import os

from utils.utils import load_config

CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config",
    "scoring_config.json",
)

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def compute_risk_score(findings, config=None):
    """Aggregate findings into a single global risk level.

    Args:
        findings (list[Finding]): All findings from the analysis.
        config (dict): Optional pre-loaded scoring config. Loaded from
            CONFIG_PATH if not provided. (Used for testing)

    Returns:
        dict: {"level": str, "counts": dict[str, int]}
    """
    if config is None:
        config = load_config(CONFIG_PATH)

    counts = dict.fromkeys(SEVERITIES, 0)
    for f in findings:
        if f.combo_only:
            continue
        if f.severity in counts:
            counts[f.severity] += 1

    for rule in config.get("rules", []):
        min_counts = rule["min_counts"]

        if all(counts.get(sev, 0) >= n for sev, n in min_counts.items()):
            return {"level": rule["level"], "counts": counts}

    if sum(counts.values()) == 0:
        return {"level": "CLEAN", "counts": counts}

    return {"level": "LOW", "counts": counts}
