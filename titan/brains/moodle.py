"""Moodle platform brain.

Detects Moodle instances and specializes the scan for Moodle's known
attack surface: course modules, user enumeration, capability checks,
file upload vectors, and the REST/webservice APIs.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from titan.brains import PlatformBrain


class MoodleBrain(PlatformBrain):
    name = "moodle"

    fingerprint_markers = [
        "moodle",
        "/mod/",
        "/lib/upgradelib.php",
        "/composer.json",
        "Moodle",
        "moodlemobile",
        "/webservice/xmlrpc/server.php",
        "/lib/javascript.php",
        "/theme/",
        "/course/",
        "/user/profile.php",
        "/login/signup.php",
    ]

    def match(self, fingerprint: Dict[str, Any], html: str, headers: Dict[str, str]) -> float:
        score = 0.0
        lower_html = (html or "").lower()
        lower_headers = " ".join(str(v) for v in headers.values()).lower()
        for marker in self.fingerprint_markers:
            m = marker.lower()
            if m in lower_html:
                score += 0.25
            if m in lower_headers:
                score += 0.15
        if fingerprint.get("technologies"):
            for tech in fingerprint["technologies"]:
                if "moodle" in str(tech).lower():
                    score += 0.4
        return min(score, 1.0)

    def extra_seed_urls(self, base_url: str) -> List[str]:
        return [
            base_url.rstrip("/") + "/login/",
            base_url.rstrip("/") + "/login/signup.php",
            base_url.rstrip("/") + "/user/profile.php",
            base_url.rstrip("/") + "/course/",
            base_url.rstrip("/") + "/admin/",
            base_url.rstrip("/") + "/webservice/xmlrpc/server.php",
            base_url.rstrip("/") + "/lib/upgradelib.php",
            base_url.rstrip("/") + "/composer.json",
            base_url.rstrip("/") + "/version.php",
            base_url.rstrip("/") + "/config.php",
            base_url.rstrip("/") + "/install.php",
            base_url.rstrip("/") + "/tokenpluginfile.php",
            base_url.rstrip("/") + "/draftfile.php",
            base_url.rstrip("/") + "/tokenpluginfile.php",
            base_url.rstrip("/") + "/webservice/rest/server.php",
            base_url.rstrip("/") + "/lib/ajax/service.php",
            base_url.rstrip("/") + "/lib/ajax/service-nologin.php",
            base_url.rstrip("/") + "/user/files/index.php",
            base_url.rstrip("/") + "/badge/viewer.php",
            base_url.rstrip("/") + "/calendar/",
            base_url.rstrip("/") + "/grade/",
            base_url.rstrip("/") + "/message/",
            base_url.rstrip("/") + "/notes/",
            base_url.rstrip("/") + "/blog/",
            base_url.rstrip("/") + "/portfolio/",
            base_url.rstrip("/") + "/repository/",
            base_url.rstrip("/") + "/tag/",
            base_url.rstrip("/") + "/group/",
            base_url.rstrip("/") + "/cohort/",
            base_url.rstrip("/") + "/role/",
            base_url.rstrip("/") + "/capability/",
            base_url.rstrip("/") + "/enrol/",
            base_url.rstrip("/") + "/auth/",
            base_url.rstrip("/") + "/backup/",
            base_url.rstrip("/") + "/restore/",
            base_url.rstrip("/") + "/question/",
            base_url.rstrip("/") + "/quiz/",
            base_url.rstrip("/") + "/assign/",
            base_url.rstrip("/") + "/data/",
            base_url.rstrip("/") + "/wiki/",
            base_url.rstrip("/") + "/glossary/",
            base_url.rstrip("/") + "/feedback/",
            base_url.rstrip("/") + "/survey/",
            base_url.rstrip("/") + "/scorm/",
            base_url.rstrip("/") + "/workshop/",
            base_url.rstrip("/") + "/journal/",
            base_url.rstrip("/") + "/checklist/",
            base_url.rstrip("/") + "/customcert/",
            base_url.rstrip("/") + "/logstore/",
            base_url.rstrip("/") + "/tool/",
        ]

    def extra_parameters(self) -> List[str]:
        return [
            "sesskey", "sess_key", "session",
            "id", "course", "category", "itemid",
            "userid", "user_id", "u", "username",
            "file", "filename", "filepath", "contextid",
            "lang", "theme", "option",
            "action", "mode", "section",
            "module", "mod", "instance",
            "url", "redirect", "return",
            "token", "wsfunction", "wstoken",
            "mform_isexpanded", "idnumber", "email",
            "password", "password_hashed",
            "capability", "roleid", "contextlevel",
            "instanceid", "parent",
            "draftid", "itemid", "filearea",
            "component", "filepath", "filename",
            "qanda", "question",
            "quiz", "attempt",
            "assign", "submission",
            "data", "record",
            "wiki", "pagename",
            "glossary", "concept",
            "feedback", "item",
            "survey", "record",
            "scorm", "scoid",
            "workshop", "plan",
            "grade", "itemnumber",
            "message", "id",
            "note", "publishing",
            "blog", "entry",
            "portfolio", "call",
            "repository", "repo",
            "tag", "collection",
            "group", "groupid",
            "cohort", "cohortid",
            "enrol", "enrolid",
            "auth", "username",
            "backup", "backupid",
            "restore", "path",
            "customcert", "issueid",
            "logstore", "logstoreid",
            "tool", "toolname",
        ]

    def tag_finding(self, finding: Any) -> None:
        tags = getattr(finding, "tags", None) or []
        platform_tag = "platform:moodle"
        if platform_tag not in tags:
            tags.append(platform_tag)
        finding.tags = tags
        notes = getattr(finding, "notes", "") or ""
        if "moodle" not in notes.lower():
            finding.notes = (notes + " [Moodle platform]").strip()
