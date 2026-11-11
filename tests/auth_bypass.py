"""Authentication and authorization tests.

Transport authentication only exists for HTTP.  A stdio server inherits the
local user's privileges and cannot be meaningfully tested for missing auth, so
this module returns no findings there and documents the limitation.

For HTTP endpoints the test compares an authenticated baseline with an
unauthenticated request for the same method.  A finding requires substantive
data in the unauthenticated response, not merely the absence of an error
string.
"""
from __future__ import annotations

import logging

from core.evidence import make_finding, redact_secret
from core.protocol import (
    AuthenticationError,
    ProtocolError,
    RequestTimeout,
    SafetyLimitExceeded,
    TransportError,
    content_summary,
    error_code,
    result_of,
)

logger = logging.getLogger("mcpwn.auth")

BAD_JWTS = [
    ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
     "alg:none"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.", "missing signature"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.fake",
     "invalid signature"),
]


class AuthBypassTest:
    """Test missing authentication and weak token handling over HTTP."""

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self, tool=None):
        if not self.pentester.target_url:
            logger.info("Authorization: skipped (stdio transport has no auth)")
            return []
        findings = []
        findings.extend(self._test_missing_auth())
        findings.extend(self._test_token_replay())
        return findings

    def _auth_header_name(self):
        headers = self.pentester.config.get("headers") or {}
        for name in headers:
            if name.lower() in ("authorization", "x-api-key", "api-key"):
                return name
        return None

    def _probe(self, extra_headers=None):
        try:
            response, _ = self.pentester.send(
                "tools/list", {}, skip_analysis=True,
                extra_headers=extra_headers)
            return response, None
        except AuthenticationError as exc:
            return None, exc
        except (TransportError, ProtocolError, RequestTimeout,
                SafetyLimitExceeded, OSError) as exc:
            return None, exc

    @staticmethod
    def _has_data(response):
        if response is None or error_code(response) is not None:
            return False
        try:
            result = result_of(response)
        except ProtocolError:
            return False
        if isinstance(result, dict):
            tools = result.get("tools")
            if isinstance(tools, list):
                return bool(tools)
            return bool(result)
        return False

    def _test_missing_auth(self):
        auth_header = self._auth_header_name()
        if auth_header:
            baseline, error = self._probe()
            if error or not self._has_data(baseline):
                logger.info("Authorization: baseline request failed; "
                            "cannot test missing auth")
                return []
            response, error = self._probe({auth_header: None})
            if error:
                logger.debug("unauthenticated request rejected: %s", error)
                return []
            if self._has_data(response):
                return [make_finding(
                    "MISSING_AUTH",
                    severity="HIGH",
                    confidence=80,
                    verified=True,
                    evidence=[
                        "authenticated and unauthenticated tools/list both "
                        "returned data",
                        content_summary(response, 150),
                    ],
                    note="endpoint served data without credentials",
                )]
            return []
        # No credentials configured: report as an observation, not a break.
        response, error = self._probe({})
        if error or not self._has_data(response):
            return []
        return [make_finding(
            "MISSING_AUTH",
            severity="MEDIUM",
            confidence=35,
            evidence=[
                "no credentials were configured for this scan",
                content_summary(response, 150),
            ],
            note="endpoint served data unauthenticated; may be intentional",
        )]

    def _test_token_replay(self):
        auth_header = self._auth_header_name()
        if not auth_header:
            return []
        findings = []
        invalid = "Bearer expired.invalid.token"
        response, error = self._probe({auth_header: invalid})
        if not error and self._has_data(response):
            findings.append(make_finding(
                "BROKEN_AUTH_TOKEN",
                severity="CRITICAL",
                confidence=65,
                evidence=[
                    "token {}".format(redact_secret(invalid)),
                    content_summary(response, 150),
                ],
                note="invalid token returned data",
            ))
        if auth_header.lower() != "authorization":
            return findings
        for jwt, attack in BAD_JWTS:
            response, error = self._probe(
                {auth_header: "Bearer {}".format(jwt)})
            if error or not self._has_data(response):
                continue
            findings.append(make_finding(
                "JWT_BYPASS",
                severity="CRITICAL",
                confidence=65,
                evidence=[
                    "accepted JWT with {}".format(attack),
                    content_summary(response, 150),
                ],
                note="JWT validation appears broken",
            ))
            break
        return findings


#: Backwards-compatible alias for scripts importing the old class name.
AuthorizationTest = AuthBypassTest
