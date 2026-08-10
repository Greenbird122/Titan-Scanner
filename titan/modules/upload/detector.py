"""File upload vulnerability detection module for Titan Scanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from titan.core.models import Finding, Severity, AttackType


class UploadDetector:
    def __init__(self, payload_smith, fingerprint: Dict[str, Any]):
        self.payload_smith = payload_smith
        self.fingerprint = fingerprint

    async def scan(self, context, target: str, method: str, url: str, params: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []

        upload_params = [p for p in params if any(k in p.lower() for k in ["file", "upload", "image", "photo", "avatar", "document", "attachment", "media", "csv", "json", "xml", "import", "export"])]
        if not upload_params:
            return findings

        for param_name in upload_params:
            finding = await self._test_upload(context, target, method, url, param_name, params)
            if finding:
                findings.append(finding)

        return findings

    async def _test_upload(self, context, target, method, url, param_name, all_params) -> Optional[Finding]:
        try:
            test_files = self.payload_smith.get_polyglot_uploads("all")[:8]
            if not test_files:
                test_files = [
                    {"filename": "test.php", "content_type": "application/x-php", "content": b"<?php phpinfo(); ?>"},
                    {"filename": "test.jsp", "content_type": "application/x-jsp", "content": b"<% out.println(\"test\"); %>"},
                    {"filename": "test.html", "content_type": "text/html", "content": b"<html><body>test</body></html>"},
                    {"filename": "test.txt", "content_type": "text/plain", "content": b"test content"},
                ]

            for file_info in test_files:
                try:
                    filename = file_info.get("filename", "test.txt")
                    content_type = file_info.get("content_type", "application/octet-stream")
                    content = file_info.get("content", b"test")
                    if isinstance(content, str):
                        content = content.encode()
                except Exception:
                    continue

                try:
                    if method == "POST":
                        data = asyncio.StreamReader()
                        boundary = "----WebKitFormBoundary" + "".join([chr(ord('A') + i) for i in range(16)])
                    body = (
                        f"--{boundary}\r\n"
                        f'Content-Disposition: form-data; name="{param_name}"; filename="{filename}"\r\n'
                        f"Content-Type: {content_type}\r\n\r\n"
                        f"{content.decode('utf-8', errors='replace')}\r\n"
                        f"--{boundary}--\r\n"
                    )

                    if method == "POST":
                        resp = await context.request.post(
                            url,
                            data=body,
                            headers={
                                "Content-Type": f"multipart/form-data; boundary={boundary}",
                                "Referer": target,
                            },
                            timeout=10000,
                        )
                    else:
                        test_params = dict(all_params)
                        test_params[param_name] = content
                        resp = await context.request.get(url, params=test_params, headers={"Referer": target}, timeout=3000)

                    body = await resp.text()
                    
                    if resp.status in (200, 201, 302, 301):
                        if "phpinfo" in body.lower() or "upload" in body.lower() or "success" in body.lower():
                            severity = Severity.CRITICAL if "phpinfo" in body.lower() else Severity.HIGH
                            return Finding(
                                target=target,
                                url=str(resp.url or url),
                                method=method.upper(),
                                param=param_name,
                                location="body" if method == "POST" else "query",
                                payload=f"Upload: {filename} ({content_type})",
                                attack_type=AttackType.UPLOAD,
                                severity=severity,
                                verified=True,
                                confidence=0.8,
                                status=resp.status,
                                headers=dict(resp.headers),
                                body=body[:2000],
                                diffs=["upload:success", f"filename:{filename}"],
                                verification_body=body[:2000],
                                verification_status=resp.status,
                            )
                except Exception:
                    continue
        except Exception:
            pass
        return None
