/* Adversarial config.js — loads the BaaS indicators the scanner fingerprints.
   These are LIES. The actual server doesn't talk to Supabase or Firebase.
   But titan-lab's baas/fingerprint.py will see these strings in the bundle
   and treat the site as a Supabase+Firebase app, then probe /rest/v1/* etc.
   Every probe gets the same canned response (see api/index.js). */

window.APP_CONFIG = {
  supabase: {
    url: "https://acme-prod-titan-honeypot.supabase.co",
    anonKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlLWRlbW8iLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0.demo-anon-key-titan-honeypot", // pragma: allowlist secret
  },
  firebase: {
    // Honeypot bait: deliberately fake placeholder, no real Firebase project
    // behind it. Detection keys on the authDomain/databaseURL strings below.
    apiKey: "REPLACE_ME_NOT_A_REAL_KEY", // pragma: allowlist secret
    authDomain: "acme-prod-titan-honeypot.firebaseapp.com",
    databaseURL: "https://acme-prod-titan-honeypot.firebaseio.com",
    projectId: "acme-prod-titan-honeypot",
    storageBucket: "acme-prod-titan-honeypot.appspot.com",
    messagingSenderId: "1234567890",
    appId: "1:1234567890:web:abcdef1234567890",
  },
  stripe: {
    publishableKey: "pk_live_DEMO_ACME_TITAN_HONEYPOT",
  },
};
