"""Signature table for subdomain takeover detection.

One entry per takeover-prone service: the CNAME suffixes it hands out, the
HTTP body fragments its dangling pages return, and what a takeover is worth.
Pure data, deliberately separate from ``detector.py`` so the matching logic
stays readable and the table can be audited without wading through probes.

Maintained from public takeover-fingerprint research (can-i-take-over-xyz
and vendor docs); every fragment must be verifiable against the live
service before it earns a place here.
"""

from __future__ import annotations

from typing import Any

VULNERABLE_SERVICES: list[dict[str, Any]] = [
    # ── Vercel ───────────────────────────────────────────────────────
    {
        "service": "Vercel",
        "cnames": [".vercel.app", ".now.sh"],
        "http_fingerprint": [
            "The deployment could not be found",
            "404: NOT_FOUND",
            "DEPLOYMENT_NOT_FOUND",
            "has been removed",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary HTML/JS from the victim's subdomain.",
    },
    # ── GitHub Pages ─────────────────────────────────────────────────
    {
        "service": "GitHub Pages",
        "cnames": [".github.io"],
        "http_fingerprint": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an",
            "https://pages.github.com/",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── AWS S3 ───────────────────────────────────────────────────────
    {
        "service": "AWS S3",
        "cnames": [".s3.amazonaws.com", ".s3-website", ".s3-us-east-1.amazonaws.com"],
        "http_fingerprint": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "AccessDenied",
        ],
        "dns_fingerprint": "NXDOMAIN",
        "severity": "critical",
        "takeover_impact": "Host arbitrary content; potential credential harvesting via S3 bucket claim.",
    },
    # ── Heroku ───────────────────────────────────────────────────────
    {
        "service": "Heroku",
        "cnames": [".herokudns.com", ".herokuapp.com", ".herokuspace.com"],
        "http_fingerprint": [
            "No such app",
            "no-hierarchical-app",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── Netlify ──────────────────────────────────────────────────────
    {
        "service": "Netlify",
        "cnames": [".netlify.app", ".netlify.com"],
        "http_fingerprint": [
            "Not Found - Request ID:",
            "netlify/pages",
            "You haven't deployed a site yet",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── Shopify ──────────────────────────────────────────────────────
    {
        "service": "Shopify",
        "cnames": [".myshopify.com"],
        "http_fingerprint": [
            "Sorry, this shop is currently unavailable.",
            "Only one step left!",
            "Site Unavailable",
        ],
        "severity": "high",
        "takeover_impact": "E-commerce takeover — phish payment credentials via fake storefront.",
    },
    # ── Fastly ───────────────────────────────────────────────────────
    {
        "service": "Fastly",
        "cnames": [".global.ssl.fastly.net", ".fastly.net"],
        "http_fingerprint": [
            "Fastly error: unknown domain",
            "Request failed",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content via Fastly CDN.",
    },
    # ── Surge ────────────────────────────────────────────────────────
    {
        "service": "Surge",
        "cnames": [".surge.sh"],
        "http_fingerprint": [
            "project not found",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content.",
    },
    # ── Azure ────────────────────────────────────────────────────────
    {
        "service": "Azure (Traffic Manager)",
        "cnames": [".trafficmanager.net", ".azurewebsites.net", ".cloudapp.net"],
        "http_fingerprint": [
            "404 Web Site not found",
            "Azure Web App - Your web app is running and waiting for your content",
            "doesn't exist in this subscription",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── Pantheon ─────────────────────────────────────────────────────
    {
        "service": "Pantheon",
        "cnames": [".pantheonsite.io"],
        "http_fingerprint": [
            "404 error unknown site!",
            "The gods are wise",
            "Pantheon",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── Tumblr ───────────────────────────────────────────────────────
    {
        "service": "Tumblr",
        "cnames": [".domains.tumblr.com"],
        "http_fingerprint": [
            "Whatever you were looking for doesn't currently exist at this address",
            "There's nothing here.",
        ],
        "severity": "high",
        "takeover_impact": "Blog takeover — post content under the victim's domain.",
    },
    # ── Zendesk ──────────────────────────────────────────────────────
    {
        "service": "Zendesk",
        "cnames": [".zendesk.com"],
        "http_fingerprint": [
            "Help Center Closed",
            "This help center no longer exists",
        ],
        "severity": "high",
        "takeover_impact": "Support portal takeover — phish customer credentials and data.",
    },
    # ── Intercom ─────────────────────────────────────────────────────
    {
        "service": "Intercom",
        "cnames": [".custom.intercom.help"],
        "http_fingerprint": [
            "This page is reserved for artistic dogs",
            "Uh oh. That page doesn't exist.",
        ],
        "severity": "high",
        "takeover_impact": "Chat widget takeover — intercept customer conversations.",
    },
    # ── WordPress.com ────────────────────────────────────────────────
    {
        "service": "WordPress.com",
        "cnames": [".wordpress.com"],
        "http_fingerprint": [
            "Do you want to register",
        ],
        "severity": "medium",
        "takeover_impact": "Blog takeover — publish content under the victim's domain.",
    },
    # ── Ghost ────────────────────────────────────────────────────────
    {
        "service": "Ghost (Pro)",
        "cnames": [".ghost.io"],
        "http_fingerprint": [
            "The thing you were looking for is no longer here",
        ],
        "severity": "high",
        "takeover_impact": "CMS takeover — full control of the victim's blog/platform.",
    },
    # ── StatusPage ───────────────────────────────────────────────────
    {
        "service": "StatusPage",
        "cnames": [".statuspage.io"],
        "http_fingerprint": [
            "Better StatusPage",
            "Micro Status Page",
        ],
        "severity": "medium",
        "takeover_impact": "Fake status page — mislead users about service health.",
    },
    # ── Helpjuice ────────────────────────────────────────────────────
    {
        "service": "Helpjuice",
        "cnames": [".helpjuice.com"],
        "http_fingerprint": [
            "We could not find what you're looking for",
        ],
        "severity": "high",
        "takeover_impact": "Knowledge base takeover — serve phishing content.",
    },
    # ── Helpscout ────────────────────────────────────────────────────
    {
        "service": "Helpscout",
        "cnames": [".helpscoutdocs.com"],
        "http_fingerprint": [
            "No settings were found for this company",
        ],
        "severity": "high",
        "takeover_impact": "Documentation takeover — phish users via trusted domain.",
    },
    # ── Campaignmonitor ──────────────────────────────────────────────
    {
        "service": "Campaignmonitor",
        "cnames": [".createsend.com", ".campaignmonitor.com"],
        "http_fingerprint": [
            "Double check the URL",
            "Trying to access your account?",
        ],
        "severity": "medium",
        "takeover_impact": "Email campaign takeover — send phishing emails from victim's domain.",
    },
    # ── Cargocollective ──────────────────────────────────────────────
    {
        "service": "Cargocollective",
        "cnames": [".cargocollective.com"],
        "http_fingerprint": [
            "If you're moving your domain away from Cargo you must make this configuration change",
        ],
        "severity": "high",
        "takeover_impact": "Portfolio takeover — serve arbitrary content.",
    },
    # ── Feedpress ────────────────────────────────────────────────────
    {
        "service": "Feedpress",
        "cnames": [".feedpress.me"],
        "http_fingerprint": [
            "The feed has not been found",
        ],
        "severity": "medium",
        "takeover_impact": "RSS feed takeover — serve malicious content to subscribers.",
    },
    # ── Google Cloud ─────────────────────────────────────────────────
    {
        "service": "Google Cloud Storage",
        "cnames": [".c.storage.googleapis.com"],
        "http_fingerprint": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "severity": "critical",
        "takeover_impact": "Storage takeover — serve arbitrary files from victim's subdomain.",
    },
    # ── Instapage ────────────────────────────────────────────────────
    {
        "service": "Instapage",
        "cnames": [".instapage.com"],
        "http_fingerprint": [
            "The page you are looking for can't be found",
        ],
        "severity": "medium",
        "takeover_impact": "Landing page takeover — phish via fake campaign page.",
    },
    # ── LaunchRock ───────────────────────────────────────────────────
    {
        "service": "LaunchRock",
        "cnames": [".launchrock.com"],
        "http_fingerprint": [
            "It looks like you may have taken a wrong turn somewhere",
        ],
        "severity": "medium",
        "takeover_impact": "Coming soon page takeover — serve phishing content.",
    },
    # ── Mindbox ──────────────────────────────────────────────────────
    {
        "service": "Mindbox",
        "cnames": [".mindbox.io"],
        "http_fingerprint": [
            "Unexpected end-of-file",
        ],
        "severity": "low",
        "takeover_impact": "Limited — marketing automation platform.",
    },
    # ── Pingdom ──────────────────────────────────────────────────────
    {
        "service": "Pingdom",
        "cnames": [".stats.pingdom.com"],
        "http_fingerprint": [
            "Sorry, couldn't find the status page",
        ],
        "severity": "low",
        "takeover_impact": "Status page takeover — fake uptime reports.",
    },
    # ── Proposify ────────────────────────────────────────────────────
    {
        "service": "Proposify",
        "cnames": [".proposify.biz"],
        "http_fingerprint": [
            "If you need immediate assistance, please contact",
        ],
        "severity": "medium",
        "takeover_impact": "Proposal tool takeover — phish business contacts.",
    },
    # ── Readme.io ────────────────────────────────────────────────────
    {
        "service": "Readme.io",
        "cnames": [".readme.io"],
        "http_fingerprint": [
            "Project doesn't exist",
        ],
        "severity": "medium",
        "takeover_impact": "API documentation takeover — serve malicious docs.",
    },
    # ── Squarespace ──────────────────────────────────────────────────
    {
        "service": "Squarespace",
        "cnames": [".squarespace.com"],
        "http_fingerprint": [
            "No Such Account",
        ],
        "severity": "high",
        "takeover_impact": "Website takeover — serve arbitrary content.",
    },
    # ── Thinkific ────────────────────────────────────────────────────
    {
        "service": "Thinkific",
        "cnames": [".thinkific.com"],
        "http_fingerprint": [
            "You may have typed the address incorrectly or you may have used an outdated link",
        ],
        "severity": "medium",
        "takeover_impact": "Course platform takeover — phish learners.",
    },
    # ── Tilda ────────────────────────────────────────────────────────
    {
        "service": "Tilda",
        "cnames": [".tilda.ws"],
        "http_fingerprint": [
            "Please go to the site settings and put the domain name in the Domain field",
        ],
        "severity": "medium",
        "takeover_impact": "Website takeover — serve arbitrary content.",
    },
    # ── Unbounce ─────────────────────────────────────────────────────
    {
        "service": "Unbounce",
        "cnames": [".unbounce.com"],
        "http_fingerprint": [
            "The requested URL was not found on this server",
            "If you're an Unbounce customer",
        ],
        "severity": "medium",
        "takeover_impact": "Landing page takeover — phish via fake campaign page.",
    },
    # ── UserVoice ────────────────────────────────────────────────────
    {
        "service": "UserVoice",
        "cnames": [".uservoice.com"],
        "http_fingerprint": [
            "This UserVoice site is currently available to authors only",
        ],
        "severity": "low",
        "takeover_impact": "Feedback portal takeover — harvest user data.",
    },
    # ── Webflow ──────────────────────────────────────────────────────
    {
        "service": "Webflow",
        "cnames": [".proxy.webflow.com", ".proxy-ssl.webflow.com"],
        "http_fingerprint": [
            "The page you are looking for doesn't exist",
        ],
        "severity": "critical",
        "takeover_impact": "Full site takeover — serve arbitrary content from the victim's subdomain.",
    },
    # ── Wishpond ─────────────────────────────────────────────────────
    {
        "service": "Wishpond",
        "cnames": [".wishpond.com"],
        "http_fingerprint": [
            "https://www.wishpond.com/404?campaign=true",
        ],
        "severity": "medium",
        "takeover_impact": "Campaign page takeover — phish via fake promotion.",
    },
    # ── WordPress (VIP / Pressable) ──────────────────────────────────
    {
        "service": "WordPress (Pressable)",
        "cnames": [".wpenginepowered.com", ".pressable.com"],
        "http_fingerprint": [
            "Do you want to register",
        ],
        "severity": "medium",
        "takeover_impact": "Blog takeover — publish content under victim's domain.",
    },
]
