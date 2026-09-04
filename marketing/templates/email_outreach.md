# Email Outreach Templates

## Template 1: Free Quick Scan (Cold)

**Subject:** I found a security issue on your website (free proof inside)

---

Hi [Name],

I was browsing [WEBSITE] and noticed something that could be a security risk. I ran a quick scan and found [brief finding — e.g., "your admin panel has no rate limiting"].

I'm not trying to sell you anything. I just think you should know.

Here's the proof — run this command yourself:
```bash
curl -sI https://[WEBSITE]/[endpoint] | grep -i "[header]"
```

If you want the full report, I'm happy to share it for free. No strings attached.

— [Your Name]
Titan Security Lab

---

## Template 2: After Completing Free Audit

**Subject:** Your security audit is ready (14 findings, 5 critical)

---

Hi [Name],

I completed the security audit on [WEBSITE] as discussed.

**Summary:**
- 14 vulnerabilities found
- 5 critical, 3 high, 4 medium, 2 low
- 4 attack chains mapped
- Total fix time: ~8 hours

**The good news:** Your [positive finding — e.g., "SQL injection protection is solid"]

**The critical finding:** [One-liner about the worst issue]

Every finding has proof — curl commands you can run yourself to verify. No theoretical risks.

**Full report attached.** Let me know if you have questions.

— [Your Name]
Titan Security Lab

---

## Template 3: Developer Outreach (After Finding Their Site)

**Subject:** Security audit on [PROJECT NAME] — free, with proof

---

Hi [Developer Name],

I noticed your project [PROJECT NAME] on [GitHub/Twitter/etc]. I ran a quick security audit on the live instance.

Found [X] vulnerabilities including [one critical one].

Here's the proof:
```bash
curl -s [proof command]
```

I corrected 2 false positives in my findings — I only report what I can prove.

If you want the full report, it's yours. Free. I believe in making the web more secure.

— [Your Name]
Titan Security Lab

---

## Template 4: Follow-up (After No Response)

**Subject:** Re: Security audit on [WEBSITE]

---

Hi [Name],

Just following up on the security audit I sent last week.

I found [critical finding] on your site. It's fixable in about [X] hours.

The full report is ready whenever you want it. No rush.

— [Your Name]

---

## Template 5: Referral Request

**Subject:** Quick favor — do you know anyone who needs a security audit?

---

Hi [Name],

I just completed a security audit on [SITE] and thought of you.

If you know anyone who runs a website and wants to know if it's secure, I'm doing free quick scans right now. Each scan finds the top 10 vulnerability classes and comes with proof.

No sales pitch. Just proof that no system is perfect.

— [Your Name]
Titan Security Lab
