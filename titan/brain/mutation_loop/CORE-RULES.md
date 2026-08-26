# Core rules for the mutation loop
# These stay in context — everything else is in files.

1. Grep every response for sensitive data (flags, tokens, keys, PII)
2. Check error messages for data leaks
3. Simple first (curl + grep), complex later
4. Three strikes then escalate
5. Validate your oracle before building on it
6. Source code read before blind extraction
7. Don't loop on dead ends (max 3 attempts per vector)
8. No finding exists until a live HTTP response proves it
9. There is always more — but know when to stop
10. Each iteration must produce NEW information or STOP
