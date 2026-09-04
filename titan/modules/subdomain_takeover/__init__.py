"""Subdomain takeover detection module.

Detects dangling CNAME records pointing to unclaimed services:
  - Vercel, GitHub Pages, AWS S3, Heroku, Netlify, Shopify, Fastly,
    Surge, Azure, Pantheon, Tumblr, Zendesk, Intercom, WordPress.com,
    Ghost, StatusPage, Helpjuice, Helpscout, Campaignmonitor, Cargocollective,
    Feedpress, Ghost.io, Google Cloud, Instapage, LaunchRock, Mindbox,
    Pingdom, Plone, Proposify, Readme.io, Squarespace, Statuspage,
    Thinkific, Tilda, Unbounce, UserVoice, Webflow, Wishpond, WordPress,
    Zendesk.

Sources:
  1. crt.sh certificate transparency log queries
  2. JavaScript/HTML subdomain reference extraction
  3. Common subdomain name brute-force (lightweight)
"""
