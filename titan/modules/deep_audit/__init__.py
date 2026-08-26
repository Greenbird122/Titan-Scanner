"""Deep Audit Module — Automated exploitation-grade probing.

Goes beyond surface scanning to:
1. Parse JavaScript for cloud service configs (Firebase, Supabase, AWS)
2. Probe cloud services directly (Auth, Firestore, Storage, Functions)
3. Test Security Rules bypass (anonymous auth, token abuse)
4. Enumerate data models and collections
5. Map full attack chains
6. Generate deterministic test suites
"""

from titan.modules.deep_audit.prober import DeepAuditor

__all__ = ["DeepAuditor"]
