"""Resource path traversal tests"""
import urllib.parse


class ResourceTraversalTest:
    """Test path traversal on resources and tools"""
    
    LEAK_MARKERS = {
        'passwd': ["root:x:0:0", "daemon:", "bin:"],
        'shadow': ["root:$", "$6$", "$y$"],
        'ssh_key': ["-----BEGIN", "PRIVATE KEY"],
        'config': ["[extensions]", "php.ini"],
        'windows': ["[boot loader]", "[operating systems]"],
        'error': ["PDO Exception", "java.io.FileNotFound"]
    }

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

        # Get payloads: LLM-generated or static
        context = {
            'tool_name': 'resources/read',
            'target_type': 'traversal',
            'previous_failure': None
        }
        payloads = self.pentester.get_payloads(context)

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

        for tool in tools:
            schema = tool.get('inputSchema', {})
            for arg_name in schema.get('properties', {}).keys():
                if any(s in arg_name.lower() for s in suspicious_args):
                    # Get payloads for this specific tool
                    context = {
                        'tool_name': tool['name'],
                        'target_type': 'traversal',
                        'schema_hints': schema
                    }
                    payloads = self.pentester.get_payloads(context)
                    
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
        # Require 2+ markers from same category for higher confidence
        for category, markers in self.LEAK_MARKERS.items():
            matches = sum(1 for m in markers if m in content_str)
            if matches >= 2:
                return True
        # Single high-confidence markers
        high_confidence = ["root:x:0:0:root", "-----BEGIN RSA PRIVATE KEY"]
        return any(marker in content_str for marker in high_confidence)
