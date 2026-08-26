"""Authentication engine for Titan Scanner."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Dict, List, Optional


class AuthEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.credentials = config.get("auth", {})
        self.tokens: Dict[str, str] = {}
        self.session_cookies: Dict[str, Any] = {}
        self.roles: List[Dict[str, Any]] = []

    async def login(self, context, page, target: str) -> bool:
        if not self.credentials:
            return False

        # SHARPEN-S2: pre-supplied credentials — the operator may hand us a
        # Bearer token, an API key, or a full session-cookie map directly (the
        # OAuth/SSO flows many real apps use can't be driven by form-filling).
        # No browser login is needed: the identity is ready immediately.
        if self.credentials.get("token"):
            self.tokens["access"] = str(self.credentials["token"])
            if self.credentials.get("token_type"):
                self.tokens["token_type"] = str(self.credentials["token_type"])
            return True
        if self.credentials.get("api_key"):
            self.tokens["api_key"] = str(self.credentials["api_key"])
            return True
        if self.credentials.get("cookies"):
            try:
                if isinstance(self.credentials["cookies"], dict):
                    self.session_cookies.update(self.credentials["cookies"])
                else:
                    self.session_cookies.update(json.loads(self.credentials["cookies"]))
                return True
            except Exception:
                pass

        login_url = self.credentials.get("url") or self._guess_login_url(target)
        if not login_url:
            return False

        try:
            await page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
        except Exception:
            return False

        username = self.credentials.get("username", "")
        password = self.credentials.get("password", "")
        username_selector = self.credentials.get("username_selector", 'input[type="text"], input[name*="user"], input[name*="email"], input[name*="phone"], input[id*="user"], input[id*="email"], input[id*="phone"]')
        password_selector = self.credentials.get("password_selector", 'input[type="password"], input[name*="pass"], input[id*="pass"]')
        submit_selector = self.credentials.get("submit_selector", 'button[type="submit"], input[type="submit"], button')

        try:
            user_el = await page.wait_for_selector(username_selector, timeout=5000)
            if user_el:
                await user_el.fill(username)
        except Exception:
            pass

        try:
            pass_el = await page.wait_for_selector(password_selector, timeout=5000)
            if pass_el:
                await pass_el.fill(password)
        except Exception:
            pass

        try:
            submit = await page.query_selector(submit_selector)
            if submit:
                await submit.click()
            else:
                await page.keyboard.press("Enter")
        except Exception:
            return False

        await page.wait_for_timeout(3000)

        token = await self._extract_token(page, context)
        if token:
            self.tokens["access"] = token
            return True

        return False

    async def login_as_role(self, context, page, target: str, role_creds: Dict[str, Any]) -> bool:
        if not role_creds:
            return False

        login_url = role_creds.get("url") or self._guess_login_url(target)
        if not login_url:
            return False

        try:
            await page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
        except Exception:
            return False

        username = role_creds.get("username", "")
        password = role_creds.get("password", "")

        try:
            user_el = await page.wait_for_selector('input[type="text"], input[name*="user"], input[name*="phone"]', timeout=5000)
            if user_el:
                await user_el.fill(username)
        except Exception:
            pass

        try:
            pass_el = await page.wait_for_selector('input[type="password"]', timeout=5000)
            if pass_el:
                await pass_el.fill(password)
        except Exception:
            pass

        try:
            submit = await page.query_selector('button[type="submit"], input[type="submit"]')
            if submit:
                await submit.click()
            else:
                await page.keyboard.press("Enter")
        except Exception:
            return False

        await page.wait_for_timeout(3000)

        token = await self._extract_token(page, context)
        if token:
            self.tokens["access"] = token
            self.tokens["role"] = role_creds.get("role", "")
            return True

        return False

    async def _extract_token(self, page, context) -> Optional[str]:
        try:
            js_token = await page.evaluate('''() => {
                const sources = [
                    () => localStorage.getItem('access_token'),
                    () => localStorage.getItem('token'),
                    () => localStorage.getItem('jwt'),
                    () => sessionStorage.getItem('access_token'),
                    () => sessionStorage.getItem('token'),
                    () => sessionStorage.getItem('jwt'),
                ];
                for (const src of sources) {
                    const val = src();
                    if (val) return val;
                }
                return null;
            }''')
            if js_token:
                return js_token
        except Exception:
            pass

        try:
            apis = []
            def capture(request):
                if '/api/' in request.url or '/auth/' in request.url:
                    apis.append(request.url)
            page.on("request", capture)
            await page.wait_for_timeout(2000)
            page.remove_listener("request", capture)
        except Exception:
            pass

        try:
            cookies = await context.cookies()
            for cookie in cookies:
                if any(k in cookie.get("name", "").lower() for k in ["token", "jwt", "session", "auth"]):
                    self.session_cookies[cookie["name"]] = cookie.get("value", "")
        except Exception:
            pass

        return None

    def _guess_login_url(self, target: str) -> Optional[str]:
        from urllib.parse import urljoin
        candidates = [
            "/login", "/api/auth/login/", "/api/login",
            "/signin", "/auth/login", "/users/login",
            "/account/login", "/session/login",
        ]
        for path in candidates:
            return urljoin(target, path)
        return None

    def get_auth_headers(self) -> Dict[str, str]:
        headers = {}
        if "access" in self.tokens:
            token_type = self.tokens.get("token_type", "Bearer")
            headers["Authorization"] = f"{token_type} {self.tokens['access']}"
        if "api_key" in self.tokens:
            # API keys ride as an X-API-Key header (the de-facto convention);
            # apps that expect a different header can pass `header_name`.
            header_name = self.credentials.get("api_key_header", "X-API-Key")
            headers[header_name] = self.tokens["api_key"]
        return headers

    def get_cookies(self) -> Dict[str, str]:
        return dict(self.session_cookies)

    def is_authenticated(self) -> bool:
        return bool(self.tokens.get("access") or self.session_cookies)

    def get_current_role(self) -> Optional[str]:
        return self.tokens.get("role")

    async def refresh_token(self, context, page, target: str) -> bool:
        refresh_token = self.tokens.get("refresh")
        if not refresh_token:
            return False

        from urllib.parse import urljoin
        refresh_url = urljoin(target, "/api/auth/refresh/")
        try:
            resp = await context.request.post(
                refresh_url,
                json={"refresh": refresh_token},
                headers={"Content-Type": "application/json"},
            )
            if resp.status == 200:
                data = await resp.json()
                new_access = data.get("access")
                if new_access:
                    self.tokens["access"] = new_access
                    return True
        except Exception:
            pass
        return False

    async def logout(self, context, page, target: str) -> bool:
        from urllib.parse import urljoin
        logout_url = urljoin(target, "/api/auth/logout/")
        try:
            await context.request.post(
                logout_url,
                headers={**self.get_auth_headers(), "Content-Type": "application/json"},
            )
        except Exception:
            pass

        self.tokens.clear()
        self.session_cookies.clear()
        return True
