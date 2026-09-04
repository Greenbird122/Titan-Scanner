# Titan Security Lab — Infrastructure Specification

**Version:** 1.0
**Date:** 2026-08-30
**Status:** Draft — For Future Implementation

---

## 1. Executive Summary

This document specifies the production infrastructure for Titan Security Lab — a professional penetration testing platform. The current system is a CLI-based scanner with JSON file storage. This spec outlines the transition to a full-stack web application with API, database, authentication, and automation capabilities.

**Goal:** Transform Titan from a CLI tool into a SaaS platform that can serve multiple clients concurrently with automated scanning, professional reporting, and secure access control.

---

## 2. Current State

### What Exists

| Component | Status | Limitations |
|-----------|--------|-------------|
| Titan Scanner (37 modules) | ✅ Production | CLI-only, single-target |
| Deep-Attacker Skill | ✅ Production | Manual AI-assisted |
| Findings Storage | ⚠️ Partial | JSON files on disk |
| Consent System | ✅ Production | Signed JSON files |
| Marketing Materials | ✅ Complete | Landing page ready |
| Docker Setup | ✅ Production | Single container |
| Test Suite | ✅ Complete | 65+ tests |

### What's Missing

| Component | Priority | Impact |
|-----------|----------|--------|
| Database | HIGH | Can't query across targets |
| API Server | HIGH | No automation |
| Authentication | HIGH | No access control |
| Dashboard | MEDIUM | No professional UI |
| Queue System | MEDIUM | Single scan at a time |
| Monitoring | MEDIUM | No observability |
| CI/CD | LOW | Manual deployments |

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                            │
├─────────────────────────────────────────────────────────────────┤
│  Web Dashboard (React)  │  REST API Consumer  │  CLI (Current) │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                        API GATEWAY                              │
│  FastAPI │ JWT Auth │ Rate Limit │ CORS │ WebSocket │ Logging  │
└─────────────────────────────────────────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  SCANNER ENGINE  │  │    DATABASE     │  │  QUEUE SYSTEM   │
│  (Titan Core)    │  │  (PostgreSQL)   │  │    (Redis)      │
│  37 modules      │  │  findings       │  │  scan jobs      │
│  AI integration  │  │  consent        │  │  webhooks       │
│  Deep-Attacker   │  │  users          │  │  notifications  │
└─────────────────┘  └─────────────────┘  └─────────────────┘
          │                    │                    │
          ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  FILE STORAGE    │  │     CACHE       │  │     LOGS        │
│  (Local/S3)      │  │   (Redis)       │  │   (Loki)        │
│  Reports         │  │  Sessions       │  │  Audit trail    │
│  Exploit tools   │  │  Rate limits    │  │  Metrics        │
│  Consent files   │  │  Scan results   │  │  Errors         │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## 4. Component Specifications

### 4.1 Database (PostgreSQL)

**Purpose:** Store all structured data — findings, users, consent, scan history.

**Schema:**

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'viewer',  -- admin, operator, viewer
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP
);

-- Targets table
CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url VARCHAR(2048) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    owner_id UUID REFERENCES users(id),
    consent_file VARCHAR(500),
    consent_signed_at TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending',  -- pending, scanning, completed, failed
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Findings table
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES targets(id),
    finding_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,  -- critical, high, medium, low, info
    confidence FLOAT DEFAULT 0.0,
    verified BOOLEAN DEFAULT FALSE,
    tier VARCHAR(50) DEFAULT 'suspicious',  -- confirmed, suspicious, none
    url VARCHAR(2048),
    method VARCHAR(10),
    param VARCHAR(255),
    payload TEXT,
    evidence TEXT,
    cvss_score FLOAT,
    cvss_vector VARCHAR(255),
    poc_curl TEXT,
    poc_python TEXT,
    chain JSONB DEFAULT '[]',
    tags JSONB DEFAULT '[]',
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Scans table
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES targets(id),
    status VARCHAR(50) DEFAULT 'queued',  -- queued, running, completed, failed
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    duration_seconds FLOAT,
    findings_count INTEGER DEFAULT 0,
    verified_count INTEGER DEFAULT 0,
    config_snapshot JSONB,
    errors JSONB DEFAULT '[]',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Consent table
CREATE TABLE consent (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES targets(id),
    owner_name VARCHAR(255) NOT NULL,
    owner_email VARCHAR(255) NOT NULL,
    signed_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    scope VARCHAR(50) DEFAULT 'full_audit',
    signature_hash VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_findings_target ON findings(target_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_verified ON findings(verified);
CREATE INDEX idx_scans_target ON scans(target_id);
CREATE INDEX idx_scans_status ON scans(status);
```

**Deployment:**
- PostgreSQL 15+ on managed service (AWS RDS, Supabase, or self-hosted)
- Connection pooling via PgBouncer
- Automated backups daily
- Point-in-time recovery enabled

### 4.2 API Server (FastAPI)

**Purpose:** REST API for all operations — scanning, findings, users, consent.

**Endpoints:**

```yaml
# Authentication
POST   /api/auth/login          # Login, get JWT
POST   /api/auth/register       # Register new user
POST   /api/auth/refresh        # Refresh JWT
GET    /api/auth/me              # Get current user

# Users
GET    /api/users                # List users (admin only)
GET    /api/users/{id}           # Get user
PUT    /api/users/{id}           # Update user
DELETE /api/users/{id}           # Delete user (admin only)

# Targets
POST   /api/targets              # Add new target
GET    /api/targets              # List targets
GET    /api/targets/{id}         # Get target details
PUT    /api/targets/{id}         # Update target
DELETE /api/targets/{id}         # Delete target
POST   /api/targets/{id}/consent # Upload consent file
GET    /api/targets/{id}/consent # Get consent status

# Scans
POST   /api/scans                # Start new scan
GET    /api/scans                # List scans
GET    /api/scans/{id}           # Get scan details
POST   /api/scans/{id}/cancel    # Cancel running scan
GET    /api/scans/{id}/progress  # WebSocket for real-time progress

# Findings
GET    /api/findings             # List all findings
GET    /api/findings/{id}        # Get finding details
GET    /api/findings/target/{id} # Get findings for target
GET    /api/findings/stats       # Get statistics
PUT    /api/findings/{id}        # Update finding (add notes)
DELETE /api/findings/{id}        # Delete finding

# Reports
GET    /api/reports/{target_id}  # Generate report
GET    /api/reports/{target_id}/pdf  # Download PDF
GET    /api/reports/{target_id}/disclosure  # Download disclosure

# Dashboard
GET    /api/dashboard/overview   # Dashboard stats
GET    /api/dashboard/trends     # Finding trends over time
GET    /api/dashboard/severity   # Severity distribution
```

**Authentication:**
- JWT tokens with 24h expiry
- Refresh tokens with 30d expiry
- Role-based access control (RBAC)
- Rate limiting per user (100 requests/hour)

**Deployment:**
- FastAPI on Uvicorn with Gunicorn
- Docker container behind Nginx
- TLS termination at load balancer
- Health checks at `/health`

### 4.3 Queue System (Redis + Celery)

**Purpose:** Manage concurrent scans, background jobs, notifications.

**Queues:**

```python
# Queue definitions
SCAN_QUEUE = "titan:scans"           # Scan jobs
NOTIFICATION_QUEUE = "titan:notify"  # Email/webhook notifications
REPORT_QUEUE = "titan:reports"       # Report generation
CLEANUP_QUEUE = "titan:cleanup"      # Old data cleanup

# Worker configuration
CELERY_CONFIG = {
    "broker_url": "redis://localhost:6379/0",
    "result_backend": "redis://localhost:6379/1",
    "task_serializer": "json",
    "result_serializer": "json",
    "accept_content": ["json"],
    "timezone": "UTC",
    "enable_utc": True,
    "task_track_started": True,
    "task_acks_late": True,
    "worker_prefetch_multiplier": 1,
    "worker_max_tasks_per_child": 100,
}
```

**Task Definitions:**

```python
# Scan task
@celery_app.task(bind=True, max_retries=3)
def run_scan(self, target_id: str, config: dict):
    """Run a full scan against a target."""
    # 1. Load target and consent
    # 2. Initialize Titan engine
    # 3. Run scan with progress updates
    # 4. Store findings in database
    # 5. Generate report
    # 6. Send notifications

# Report generation task
@celery_app.task
def generate_report(target_id: str, format: str = "pdf"):
    """Generate report for a target."""
    # 1. Load findings from database
    # 2. Generate markdown report
    # 3. Convert to PDF if requested
    # 4. Store in file system
    # 5. Return download URL

# Notification task
@celery_app.task
def send_notification(user_id: str, event: str, data: dict):
    """Send notification to user."""
    # 1. Load user preferences
    # 2. Send email if enabled
    # 3. Send webhook if configured
    # 4. Log notification
```

**Deployment:**
- Redis 7+ for broker and result backend
- Celery workers with autoscaling (2-8 workers)
- Flower for monitoring (optional)
- Dead letter queue for failed tasks

### 4.4 Dashboard (React)

**Purpose:** Professional web interface for managing scans and viewing findings.

**Pages:**

```
/                      # Landing page (static)
/login                 # Login page
/register              # Registration page
/dashboard             # Main dashboard
  /overview            # Stats, recent scans, charts
  /targets             # List of targets
  /targets/{id}        # Target details + findings
  /scans               # Scan history
  /scans/{id}          # Scan details + progress
  /findings            # All findings (searchable)
  /findings/{id}       # Finding details + proof
  /reports             # Generated reports
  /settings            # User settings
  /api-keys            # API key management
```

**Components:**

```typescript
// Dashboard overview
interface DashboardStats {
  totalTargets: number;
  totalScans: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  recentScans: Scan[];
  findingsTrend: TrendData[];
}

// Target list
interface Target {
  id: string;
  url: string;
  slug: string;
  status: 'pending' | 'scanning' | 'completed' | 'failed';
  consentStatus: 'pending' | 'signed' | 'expired';
  findingsCount: number;
  lastScan: Date;
  createdAt: Date;
}

// Finding detail
interface Finding {
  id: string;
  targetType: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  verified: boolean;
  tier: 'confirmed' | 'suspicious' | 'none';
  url: string;
  method: string;
  param: string;
  payload: string;
  evidence: string;
  cvssScore: number;
  cvssVector: string;
  pocCurl: string;
  pocPython: string;
  chain: string[];
  tags: string[];
  notes: string;
}
```

**Tech Stack:**
- React 18+ with TypeScript
- Tailwind CSS for styling
- Recharts for charts
- React Query for data fetching
- React Router for navigation
- Shadcn/UI for components

**Deployment:**
- Static build served by Nginx
- CDN for assets (Cloudflare)
- Environment variables for API URL

### 4.5 Authentication & Authorization

**Purpose:** Secure access to the platform.

**JWT Structure:**

```json
{
  "sub": "user-id",
  "email": "user@example.com",
  "role": "operator",
  "iat": 1693401600,
  "exp": 1693488000
}
```

**Roles:**

| Role | Permissions |
|------|-------------|
| **admin** | Full access — users, targets, scans, findings, settings |
| **operator** | Create targets, run scans, view findings, generate reports |
| **viewer** | View-only access to findings and reports |

**API Key Authentication:**

```python
# API keys for programmatic access
# Stored hashed in database
# Can be scoped to specific targets
# Rate limited per key

POST /api/auth/api-keys
{
  "name": "CI/CD Pipeline",
  "scopes": ["scans:write", "findings:read"],
  "target_ids": ["target-1", "target-2"],  # Optional: restrict to specific targets
  "expires_at": "2027-08-30"
}
```

**Rate Limiting:**

```
Authenticated users: 100 requests/hour
API keys: 1000 requests/hour
Anonymous: 10 requests/hour (landing page only)
```

### 4.6 File Storage

**Purpose:** Store reports, exploit tools, consent files.

**Structure:**

```
storage/
├── reports/
│   ├── {target-slug}/
│   │   ├── report.md
│   │   ├── report.pdf
│   │   ├── disclosure.md
│   │   └── findings.json
├── exploits/
│   ├── {target-slug}/
│   │   ├── data_extractor.py
│   │   ├── account_creator.py
│   │   └── ...
├── consent/
│   ├── {target-slug}.json
│   └── {target-slug}.pdf
└── uploads/
    └── {user-id}/
        └── ...
```

**Options:**

| Option | Cost | Pros | Cons |
|--------|------|------|------|
| **Local filesystem** | Free | Simple | No redundancy, no CDN |
| **AWS S3** | ~$0.023/GB | Scalable, CDN built-in | Cost, complexity |
| **Cloudflare R2** | Free tier | S3-compatible, no egress fees | Newer service |
| **Supabase Storage** | Free tier | Integrated with Supabase | Limited free tier |

**Recommendation:** Start with local filesystem, migrate to R2/S3 when needed.

### 4.7 Monitoring & Logging

**Purpose:** Observe system health, track errors, audit actions.

**Components:**

```yaml
# Logging
logging:
  level: INFO
  format: json
  outputs:
    - stdout
    - file: /var/log/titan/app.log
    - loki: http://localhost:3100

# Metrics
metrics:
  enabled: true
  port: 9090
  endpoints:
    - /metrics  # Prometheus format

# Alerting
alerting:
  enabled: true
  channels:
    - email
    - webhook
  rules:
    - name: scan_failed
      condition: scan.status == 'failed'
      severity: warning
    - name: critical_finding
      condition: finding.severity == 'critical'
      severity: critical
    - name: system_error
      condition: error_count > 10
      severity: critical
```

**Dashboards:**
- System health (CPU, memory, disk)
- Scan metrics (duration, success rate, findings per scan)
- API metrics (request rate, latency, errors)
- Business metrics (targets, users, revenue)

---

## 5. Deployment Architecture

### 5.1 Development

```yaml
# docker-compose.dev.yml
services:
  api:
    build: ./api
    ports:
      - "8000:8000"
    volumes:
      - ./api:/app
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/titan
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=dev-secret-key
    command: uvicorn main:app --reload --host 0.0.0.0

  worker:
    build: ./api
    command: celery -A worker worker -l info
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/titan
      - REDIS_URL=redis://redis:6379/0

  dashboard:
    build: ./dashboard
    ports:
      - "3000:3000"
    volumes:
      - ./dashboard/src:/app/src
    environment:
      - REACT_APP_API_URL=http://localhost:8000

  db:
    image: postgres:15
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=titan
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

### 5.2 Production

```yaml
# docker-compose.prod.yml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - api
      - dashboard

  api:
    build: ./api
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '2'
          memory: 2G
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - SECRET_KEY=${SECRET_KEY}
    command: gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker

  worker:
    build: ./api
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '4'
          memory: 4G
    command: celery -A worker worker -l info -c 4

  dashboard:
    build: ./dashboard
    volumes:
      - ./dashboard/build:/usr/share/nginx/html

  db:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=${POSTGRES_DB}
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

  redis:
    image: redis:7
    volumes:
      - redis_data:/data

  loki:
    image: grafana/loki:2.9.0
    ports:
      - "3100:3100"

volumes:
  postgres_data:
  redis_data:
```

### 5.3 Cloud Deployment (AWS)

```
┌─────────────────────────────────────────────────────────┐
│                    AWS Cloud                             │
├─────────────────────────────────────────────────────────┤
│  Route 53 (DNS) → CloudFront (CDN) → ALB (Load Balancer)│
└─────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────┐
│  ECS Fargate Cluster                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │ API Service  │  │ Worker Pool │  │ Dashboard   │    │
│  │ (2 tasks)    │  │ (2-8 tasks) │  │ (Static)    │    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
└─────────────────────────────────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  RDS PostgreSQL  │  │  ElastiCache    │  │  S3 Bucket      │
│  (db.t3.medium)  │  │  Redis          │  │  (Reports)      │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

**Cost Estimate (AWS):**

| Service | Configuration | Monthly Cost |
|---------|---------------|--------------|
| ECS Fargate | 2 API + 2 Worker tasks | ~$150 |
| RDS PostgreSQL | db.t3.medium, 20GB | ~$50 |
| ElastiCache Redis | cache.t3.micro | ~$15 |
| S3 | 10GB storage | ~$1 |
| CloudFront | 100GB transfer | ~$10 |
| Route 53 | 1 hosted zone | ~$1 |
| ALB | Low traffic | ~$15 |
| **Total** | | **~$240/month** |

---

## 6. Security Considerations

### 6.1 Data Protection

- All data at rest encrypted (AES-256)
- All data in transit encrypted (TLS 1.3)
- Database backups encrypted
- API keys hashed with bcrypt
- JWT secrets rotated monthly
- Consent files signed with Ed25519

### 6.2 Access Control

- Role-based access control (RBAC)
- API key scoping (per-target, per-action)
- Rate limiting per user/key
- IP allowlisting (optional)
- Audit logging for all actions

### 6.3 Network Security

- VPC with private subnets for database/cache
- Security groups restricting traffic
- WAF on CloudFront/ALB
- DDoS protection (Cloudflare/AWS Shield)
- No public access to database/cache

### 6.4 Application Security

- Input validation on all endpoints
- SQL injection prevention (parameterized queries)
- XSS prevention (output encoding)
- CSRF protection (SameSite cookies)
- Content Security Policy headers
- Rate limiting on auth endpoints

---

## 7. Migration Plan

### Phase 1: Database + API (Week 1-2)

1. Set up PostgreSQL database
2. Create schema and migrations
3. Build FastAPI server with core endpoints
4. Add JWT authentication
5. Migrate existing JSON findings to database

### Phase 2: Dashboard (Week 3)

1. Build React dashboard
2. Add login/register pages
3. Build target management UI
4. Build findings viewer
5. Add report generation

### Phase 3: Queue + Automation (Week 4)

1. Set up Redis + Celery
2. Add scan queue
3. Add background job processing
4. Add webhook notifications
5. Add email notifications

### Phase 4: Production Deployment (Week 5-6)

1. Set up AWS/cloud infrastructure
2. Configure CI/CD pipeline
3. Add monitoring and logging
4. Performance testing
5. Security audit

### Phase 5: Polish + Launch (Week 7-8)

1. UI/UX improvements
2. Documentation
3. Beta testing
4. Bug fixes
5. Public launch

---

## 8. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| API uptime | 99.9% | Monitoring |
| Scan completion rate | 95% | Database |
| Average scan duration | <10 minutes | Database |
| API response time | <200ms | Metrics |
| Dashboard load time | <2 seconds | Monitoring |
| User satisfaction | >4.5/5 | Surveys |

---

## 9. Open Questions

1. **Multi-tenancy:** Should we support multiple organizations or keep single-tenant?
2. **Pricing model:** Per-scan, subscription, or hybrid?
3. **Data retention:** How long to keep scan results?
4. **Compliance:** Any regulatory requirements (GDPR, SOC2)?
5. **Support:** What level of support to offer?

---

## 10. Next Steps

1. Review and approve this specification
2. Set up development environment
3. Begin Phase 1 implementation
4. Daily standups during implementation
5. Weekly progress reviews

---

*Document generated by Titan Security Lab infrastructure planning.*
*For questions or clarifications, contact the engineering team.*
