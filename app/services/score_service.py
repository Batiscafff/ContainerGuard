WEIGHTS = {
    "critical": 20,
    "high": 10,
    "medium": 3,
    "low": 1,
    "negligible": 0,
}

MAX_PENALTY = 100


def calculate_score(vulnerabilities: list[dict]) -> int:
    penalty = sum(WEIGHTS.get(v["severity"], 0) for v in vulnerabilities)
    return max(0, 100 - int((penalty / MAX_PENALTY) * 100))
