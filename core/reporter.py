"""Report generation for findings"""
import json
from datetime import datetime
from html import escape


class Reporter:
    """Generate structured reports from findings"""
    def __init__(self):
        self.findings = []

    def add_findings(self, test_name, findings):
        """Add findings from a test"""
        for finding in findings:
            finding['test'] = test_name
            finding['timestamp'] = datetime.utcnow().isoformat()
            self.findings.append(finding)

    def to_json(self, filepath):
        """Export findings as JSON"""
        report = {
            'tool': 'Mcpwn',
            'version': '1.0',
            'timestamp': datetime.utcnow().isoformat(),
            'findings': self.findings,
            'summary': {
                'total': len(self.findings),
                'by_type': self._count_by_type(),
                'by_severity': self.summary()
            }
        }
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)

    def to_html(self, filepath):
        """Export findings as HTML"""
        html = f"""<!DOCTYPE html>
<html>
<head><title>Mcpwn Report</title>
<style>
body {{ font-family: monospace; margin: 20px; }}
.finding {{ border: 1px solid #ccc; margin: 10px 0; padding: 10px; }}
.critical {{ background: #fee; }}
.high {{ background: #ffd; }}
</style>
</head>
<body>
<h1>Mcpwn Security Report</h1>
<p>Total Findings: {len(self.findings)}</p>
"""
        for f in self.findings:
            severity = escape(str(f.get('type', 'INFO')))
            test_name = escape(str(f.get('test', '')))
            finding_json = escape(json.dumps(f, indent=2))
            html += f'<div class="finding {severity.lower()}">'
            html += f'<strong>{test_name}</strong><br>'
            html += f'<pre>{finding_json}</pre></div>'
        html += '</body></html>'

        with open(filepath, 'w') as f:
            f.write(html)

    def _count_by_type(self):
        """Count findings by type"""
        counts = {}
        for f in self.findings:
            ftype = f.get('type', 'UNKNOWN')
            counts[ftype] = counts.get(ftype, 0) + 1
        return counts
    
    def summary(self):
        """Return severity breakdown"""
        from collections import Counter
        severities = Counter(f.get('severity', 'UNKNOWN') for f in self.findings)
        return dict(severities)
