"""Static fingerprint signature tables for TechFingerprinter.

Pure data - no logic lives here. Extracted from titan/core/fingerprint.py
so the detection methods stay readable and the tables stay auditable.
"""

from __future__ import annotations

COOKIE_SIGNATURES: dict[str, str] = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "sessionid": "Django/Flask",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "rack.session": "Ruby/Rack",
    "express.sid": "Express",
    "connect.sid": "Express",
    "_rails_session": "Ruby on Rails",
    "play_session": "Play Framework",
    "sid": "Node.js",
    "csrftoken": "Django",
    "_csrf": "Express/Angular",
    "XSRF-TOKEN": "Laravel",
    "AWSALB": "AWS ALB",
    "AWSALBCORS": "AWS ALB CORS",
    "BIGIPSERVER": "F5 BIG-IP",
    "BIGIP": "F5 BIG-IP",
}
