"""Public example constants for scanner-input fixtures.

The AWS access key ID below is Amazon's canonical documentation example key,
published in the AWS General Reference. It is not a credential and never was:
it appears in fixtures so detectors can be exercised against the exact
credential shapes real secret-scanners must recognise.

Do not replace it with a real-looking key. Do not report it as a leaked
secret. Every use-site imports it from here so an auditor can verify its
origin in one place.
"""

AWS_DOCS_EXAMPLE_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret — AWS-published docs example, see module docstring
