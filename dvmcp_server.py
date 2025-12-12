#!/usr/bin/env python3
"""DVMCP - Damn Vulnerable MCP Server for testing Mcpwn"""
import json
import sys
import subprocess
import os


def send_response(response):
    """Send JSON-RPC response"""
    print(json.dumps(response), flush=True)


def handle_request(request):
    """Handle incoming JSON-RPC requests"""
    method = request.get('method')
    params = request.get('params', {})
    req_id = request.get('id')
    
    if method == 'initialize':
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'protocolVersion': '2024-11-05',
                'capabilities': {'tools': {}, 'resources': {}},
                'serverInfo': {'name': 'dvmcp', 'version': '1.0'}
            }
        }
    
    if method == 'tools/list':
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'tools': [
                    {
                        'name': 'execute_command',
                        'description': 'Execute system command (VULNERABLE)',
                        'inputSchema': {
                            'type': 'object',
                            'properties': {
                                'command': {'type': 'string'}
                            },
                            'required': ['command']
                        }
                    },
                    {
                        'name': 'read_file',
                        'description': 'Read file (VULNERABLE)',
                        'inputSchema': {
                            'type': 'object',
                            'properties': {
                                'path': {'type': 'string'}
                            },
                            'required': ['path']
                        }
                    }
                ]
            }
        }
    
    if method == 'tools/call':
        tool_name = params.get('name')
        args = params.get('arguments', {})
        
        if tool_name == 'execute_command':
            # VULNERABLE: Direct command execution
            cmd = args.get('command', '')
            try:
                output = subprocess.check_output(cmd, shell=True, text=True, timeout=5)
                return {
                    'jsonrpc': '2.0',
                    'id': req_id,
                    'result': {'content': [{'type': 'text', 'text': output}]}
                }
            except Exception as e:
                return {
                    'jsonrpc': '2.0',
                    'id': req_id,
                    'error': {'code': -1, 'message': str(e)}
                }
        
        elif tool_name == 'read_file':
            # FIXED: Path traversal validation
            path = args.get('path', '')
            try:
                allowed_dir = os.path.abspath('/tmp')
                resolved_path = os.path.abspath(path)
                if not resolved_path.startswith(allowed_dir + os.sep) and resolved_path != allowed_dir:
                    raise ValueError('Path traversal detected')
                with open(resolved_path, 'r') as f:
                    content = f.read()
                return {
                    'jsonrpc': '2.0',
                    'id': req_id,
                    'result': {'content': [{'type': 'text', 'text': content}]}
                }
            except Exception as e:
                return {
                    'jsonrpc': '2.0',
                    'id': req_id,
                    'error': {'code': -1, 'message': str(e)}
                }
    
    if method == 'resources/list':
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {'resources': []}
        }
    
    return {
        'jsonrpc': '2.0',
        'id': req_id,
        'error': {'code': -32601, 'message': 'Method not found'}
    }


def main():
    """Main server loop"""
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            response = handle_request(request)
            send_response(response)
        except json.JSONDecodeError as e:
            send_response({
                'jsonrpc': '2.0',
                'id': None,
                'error': {'code': -32700, 'message': f'Parse error: {e}'}
            })
        except Exception as e:
            send_response({
                'jsonrpc': '2.0',
                'id': None,
                'error': {'code': -32603, 'message': f'Internal error: {e}'}
            })


if __name__ == '__main__':
    main()
