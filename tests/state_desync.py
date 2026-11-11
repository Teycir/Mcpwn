"""Protocol state violation tests.

Each probe runs on a freshly spawned server: the previous implementation reused
an already-initialized process, so the "double initialize" check fired on every
scan even when the server correctly rejected a second initialize.
"""
from __future__ import annotations

import logging

from core.evidence import make_finding
from core.protocol import (
    JsonRpcError,
    ProtocolError,
    RequestTimeout,
    TransportError,
    error_code,
    result_of,
)

logger = logging.getLogger("mcpwn.state_desync")


class StateDesyncTest:
    """Test protocol state violations (skip/duplicate initialize)."""

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self):
        findings = []
        findings.extend(self._test_skip_initialize())
        findings.extend(self._test_double_initialize())
        self._restore()
        return findings

    def _test_skip_initialize(self):
        """tools/list before initialize must be rejected."""
        try:
            self.pentester.restart_server(initialize=False)
        except (TransportError, ProtocolError, OSError) as exc:
            logger.warning("could not start a fresh server: %s", exc)
            return []
        try:
            response, _ = self.pentester.send(
                "tools/list", {}, skip_analysis=True)
        except (TransportError, RequestTimeout, ProtocolError) as exc:
            if not self.pentester.is_alive():
                return [make_finding(
                    "STATE_CRASH", tool=None,
                    note="server died on tools/list before initialize",
                    evidence=[str(exc)], severity="HIGH",
                    confidence=70, verified=True)]
            return []
        code = error_code(response)
        if code is None:
            tools = []
            try:
                result = result_of(response)
                if isinstance(result, dict):
                    tools = result.get("tools") or []
            except JsonRpcError:
                tools = []
            return [make_finding(
                "STATE_BYPASS",
                note="tools/list succeeded before initialize",
                evidence=[
                    "returned {} tool(s) without initialization".format(
                        len(tools) if isinstance(tools, list) else 0),
                ],
                severity="MEDIUM",
                confidence=75 if tools else 50,
                verified=bool(tools),
            )]
        if code in (-32002, -32600):
            return []
        logger.debug("unexpected error for uninitialized tools/list: %s", code)
        return []

    def _test_double_initialize(self):
        """A second initialize on an initialized session is a state reset."""
        try:
            self.pentester.restart_server(initialize=False)
            self.pentester.initialize()
            session = self.pentester.session
            if session is None:
                return []
            try:
                session.initialize(force=True)
            except (JsonRpcError, ProtocolError, TransportError,
                    RequestTimeout) as exc:
                logger.debug("server rejected duplicate initialize: %s", exc)
                return []
            return [make_finding(
                "STATE_RESET",
                note="server accepted a second initialize on an initialized "
                     "session",
                evidence=["initialize returned a result twice"],
                severity="LOW",
                confidence=45,
                verified=True,
            )]
        except (TransportError, ProtocolError, RequestTimeout, OSError) as exc:
            logger.warning("double initialize test failed: %s", exc)
            return []
        finally:
            self._restore()

    def _restore(self):
        try:
            self.pentester.restart_server(initialize=True)
        except (TransportError, ProtocolError, RequestTimeout,
                OSError) as exc:
            logger.error("state desync restore failed: %s", exc)
