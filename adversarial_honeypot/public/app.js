/* Adversarial app.js — looks like a real SPA bootstrap. The fetch() calls
   to Supabase + Firebase are all intercepted client-side: we DON'T actually
   talk to those backends. Instead, our own /api/* endpoints return
   the same canned shape that a real Supabase/Firebase would.

   Trick: titan-lab's BaaS enumerator will see this code, extract the
   supabase URL via regex r'https://[a-z0-9]+\.supabase\.co', and probe
   the real supabase.co host — which returns NXDOMAIN. Our job is to
   ALSO serve canned responses on our OWN /api/* paths so any scanner
   that probes the wrong host still gets a "vulnerable-looking" body. */

(function () {
  const cfg = window.APP_CONFIG;
  console.log("[acme] booting with", cfg.supabase.url, cfg.firebase.projectId);

  const supa = window.supabase.createClient(cfg.supabase.url, cfg.supabase.anonKey);

  async function loadProducts() {
    /* Not actually a fetch to supabase — we read our own API.
       But the surface looks identical to a real supabase client call. */
    try {
      const r = await fetch("/api/rest/v1/products?select=*");
      const data = await r.json();
      return data;
    } catch (e) {
      return [];
    }
  }

  async function loadAccount() {
    try {
      const r = await fetch("/api/auth/v1/user", {
        headers: { "Authorization": "Bearer " + (localStorage.getItem("token") || "") },
      });
      if (r.ok) return await r.json();
      return null;
    } catch (e) { return null; }
  }

  window.acme = { loadProducts, loadAccount, supa, cfg };
  document.addEventListener("DOMContentLoaded", () => {
    loadProducts().then((p) => {
      const grid = document.querySelector(".grid");
      if (!grid || !p || !p.length) return;
      grid.innerHTML = p
        .map(
          (x) =>
            `<a class="card" href="/products/${encodeURIComponent(x.slug)}">${x.name}</a>`,
        )
        .join("");
    });
  });
})();
