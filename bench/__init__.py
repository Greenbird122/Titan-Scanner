"""PUSH-TO-100 Phase C — benchmark rig (runner + scorecard).

The backing: per-challenge pass rates anyone can check. A benchmark is a
manifest of KNOWN-vulnerable challenges (local_lab now; Juice Shop / WebGoat
once the operator approves the installs). The runner scans each challenge's
endpoint and scores detection — HIT (the attack type was reported for that
endpoint), MISS (not found), or N/A (challenge not reachable). The scorecard
renders the table and persists scorecard.json for the public results page.
"""
