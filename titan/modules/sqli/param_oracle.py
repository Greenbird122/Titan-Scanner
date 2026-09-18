"""Core parameter testing oracle for the SQLi detector.

Mixin for SQLiDetector: the full differential / timing / error /
sanity-pair oracle stack for a single parameter, plus the sanity-pair
opposite-payload generator.
"""

from __future__ import annotations

import time
from typing import Any

from titan.core.logger import get_logger
from titan.core.models import AttackType, Finding, Severity
from titan.verify import BaselineAnalyzer
from titan.verify.oracles import is_echo_differential

logger = get_logger("detector")


class ParamOracleMixin:
    # Host state supplied by SQLiDetector before any mixin method runs
    # (same pattern as titan/core/engine_helpers.EngineHelpersMixin).
    payload_smith: Any
    fingerprint: dict[str, Any]
    blind_detector: Any

    async def _test_param(
        self,
        context,
        target: str,
        method: str,
        url: str,
        param_name: str,
        all_params: dict[str, str],
        payloads: list[str],
    ) -> Finding | None:
        try:
            baseline_body = ""
            baseline_status = None
            baseline_times: list[float] = []

            # 1. Collect Baseline
            try:
                for _ in range(3):
                    start = time.monotonic()
                    if method == "GET":
                        r = await context.request.get(url, params=all_params, headers={"Referer": target}, timeout=3000)
                    else:
                        r = await context.request.post(url, data=all_params, headers={"Referer": target}, timeout=3000)
                    baseline_times.append(time.monotonic() - start)
                    if not baseline_body:
                        baseline_body = await r.text()
                        baseline_status = r.status
            except Exception as exc:
                logger.debug(f"suppressed exception: {exc}")
                pass

            timing_runs = 0

            # 2. Iterate through payload suite
            for payload in payloads:
                try:
                    test_params = dict(all_params)
                    test_params[param_name] = payload
                    if method == "GET":
                        resp = await context.request.get(
                            url, params=test_params, headers={"Referer": target}, timeout=3000
                        )
                    else:
                        resp = await context.request.post(
                            url, data=test_params, headers={"Referer": target}, timeout=3000
                        )
                    body = await resp.text()

                    diffs = BaselineAnalyzer.diff_responses(baseline_body, body, payload)

                    # 3. Timing Oracle (Blind SQLi)
                    is_blind, blind_time = False, 0.0
                    delay_keywords = [
                        "sleep(",
                        "sleep ",
                        "benchmark(",
                        "waitfor",
                        "pg_sleep",
                        "dbms_pipe",
                        "randomblob(",
                    ]
                    if timing_runs < 3 and any(k in payload.lower() for k in delay_keywords):
                        timing_runs += 1
                        is_blind, blind_time = await self.blind_detector.detect_time_based(
                            context,
                            url,
                            method,
                            test_params,
                            {},
                            {"Referer": target},
                            payload,
                            "query" if method == "GET" else "body",
                            baseline_times,
                            param_name=param_name,
                        )
                    if is_blind:
                        diffs.append(f"time_delay:{blind_time:.1f}s")

                    # 4. Error-Based Oracle
                    error_signatures = [
                        "sql syntax",
                        "mysql_fetch_array",
                        "ora-",
                        "postgresql",
                        "warning: mysql",
                        "syntax error",
                        "sqlstate",
                        "odbc driver",
                        "unclosed quotation mark",
                        "quoted string not properly terminated",
                        "incorrect syntax near",
                        "microsoft ole db",
                        "sqlite3.operationalerror",
                        "database error",
                        "syntax error at or near",
                        "conversion failed",
                        "query failed",
                        "db2 sql error",
                        "pg_query",
                        "org.hibernate",
                        "org.postgresql",
                        "com.mysql.jdbc",
                        "microsoft sql server",
                        "sqlite_step",
                        "driver [{",
                        "sybase",
                        "informix",
                        "ora-00933",
                        "ora-00921",
                        "ora-00936",
                        "ora-01756",
                        "ora-00904",
                    ]
                    for sig in error_signatures:
                        if sig in body.lower() and sig not in baseline_body.lower():
                            diffs.append(f"error:{sig}")
                            break

                    # 5. Sanity-Pair Boolean Oracle
                    sanity_confirmed = False
                    if (
                        "'" in payload.lower()
                        or "1=1" in payload.lower()
                        or "or" in payload.lower()
                        or "union" in payload.lower()
                        or "order by" in payload.lower()
                    ):
                        opposite = self._get_opposite_payload(payload)
                        if opposite:
                            opp_params = dict(all_params)
                            opp_params[param_name] = opposite
                            if method == "GET":
                                opp_resp = await context.request.get(
                                    url, params=opp_params, headers={"Referer": target}, timeout=3000
                                )
                            else:
                                opp_resp = await context.request.post(
                                    url, data=opp_params, headers={"Referer": target}, timeout=3000
                                )
                            opp_body = await opp_resp.text()

                            if not is_echo_differential(body, opp_body, payload, opposite):
                                sanity_confirmed = True
                                diffs.append("sanity_pair:boolean_confirmed")
                            else:
                                baseline_ok = (
                                    baseline_status is not None and baseline_status > 0 and baseline_status < 400
                                )
                                payload_ok = resp.status is not None and resp.status > 0 and resp.status < 400
                                opp_ok = opp_resp.status is not None and opp_resp.status > 0 and opp_resp.status < 400
                                if payload_ok != opp_ok and opp_ok == baseline_ok:
                                    sanity_confirmed = True
                                    diffs.append(f"sanity_pair:status_flip:{resp.status}vs{opp_resp.status}")

                    all_diffs = diffs

                    # 6. Evidence Verification Gate
                    has_error_sig = any(sig in body.lower() for sig in error_signatures)
                    sql_evidence = sanity_confirmed or has_error_sig or is_blind

                    if sql_evidence and (all_diffs or resp.status >= 500):
                        severity = Severity.CRITICAL if (resp.status >= 500 or is_blind) else Severity.HIGH
                        confidence = min(0.99, 0.5 + len(all_diffs) * 0.1)
                        if "sanity_pair:boolean_confirmed" in all_diffs:
                            confidence = max(confidence, 0.88)

                        has_real_evidence = (
                            "sanity_pair:boolean_confirmed" in all_diffs
                            or "sanity_pair:status_flip" in " ".join(all_diffs)
                            or has_error_sig
                            or is_blind
                        )

                        return Finding(
                            target=target,
                            url=str(resp.url or url),
                            method=method.upper(),
                            param=param_name,
                            location="query" if method == "GET" else "body",
                            payload=payload,
                            attack_type=AttackType.SQLI,
                            severity=severity,
                            verified=has_real_evidence,
                            confidence=confidence,
                            status=resp.status,
                            headers=dict(resp.headers),
                            body=body[:2000],
                            diffs=all_diffs,
                            baseline_body=baseline_body[:2000],
                            baseline_status=baseline_status,
                            verification_body=body[:2000],
                            verification_status=resp.status,
                        )
                except Exception as exc:
                    logger.debug(f"variant failed, continuing: {exc}")
                    continue
            return None
        except Exception:
            return None

    def _get_opposite_payload(self, payload: str) -> str | None:
        """Generate the logical opposite for sanity-pair testing."""
        pl = payload.lower().replace("/**/", "")
        if "or 1=1" in pl or "or '1'='1" in pl:
            return (
                payload.replace("OR 1=1", "AND 1=2")
                .replace("or 1=1", "AND 1=2")
                .replace("OR '1'='1", "AND '1'='2")
                .replace("or '1'='1", "AND '1'='2")
                .replace("or/**/1=1", "AND 1=2")
                .replace("OR/**/1=1", "AND 1=2")
            )
        if "and 1=1" in pl or "and '1'='1" in pl:
            return (
                payload.replace("AND 1=1", "AND 1=2")
                .replace("and 1=1", "AND 1=2")
                .replace("AND '1'='1", "AND '1'='2")
                .replace("and '1'='1", "AND '1'='2")
                .replace("and/**/1=1", "AND 1=2")
            )
        if "1=1" in pl:
            return payload.replace("1=1", "1=2")
        if "union select" in pl:
            return payload.replace("UNION SELECT", "AND 1=2--").replace("union select", "AND 1=2--")
        if "order by" in pl:
            return payload.replace("ORDER BY 1", "ORDER BY 99999").replace("order by 1", "ORDER BY 99999")
        return None
