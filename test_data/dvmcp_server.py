#!/usr/bin/env python3
"""Deliberately Vulnerable MCP Server - For Testing Mcpwn"""
import json
import sys
import subprocess
import os

def send_response(response):
    """Send JSON-RPC response"""
    sys.stdout.write(json.dumps(response) + '\n')
    sys.stdout.flush()

def handle_request(request):
    """Handle JSON-RPC request"""
    method = request.get('method')
    params = request.get('params', {})
    req_id = request.get('id')
    
    if method == 'initialize':
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'protocolVersion': '2024-11-05',
                'capabilities': {'tools': {}},
                'serverInfo': {'name': 'dvmcp', 'version': '1.0'}
            }
        }
    
    elif method == 'tools/list':
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'tools': [
                    {
                        'name': 'execute_command',
                        'description': 'Execute shell command',
                        'inputSchema': {
                            'type': 'object',
                            'properties': {
                                'command': {'type': 'string'}
                            }
                        }
                    },
                    {
                        'name': 'read_file',
                        'description': 'Read file contents',
                        'inputSchema': {
                            'type': 'object',
                            'properties': {
                                'path': {'type': 'string'}
                            }
                        }
                    }
                ]
            }
        }
    
    elif method == 'tools/call':
        tool_name = params.get('name')
        args = params.get('arguments', {})
        
        if tool_name == 'execute_command':
            # VULNERABLE: Direct command execution
            cmd = args.get('command', '')
            try:
                result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, timeout=5)
            except subprocess.TimeoutExpired:
                result = 'Command timeout'
            except Exception as e:
                result = str(e)
            
            return {
                'jsonrpc': '2.0',
                'id': req_id,
                'result': {
                    'content': [{'type': 'text', 'text': result}]
                }
            }
        
        elif tool_name == 'read_file':
            # VULNERABLE: Path traversal
            path = args.get('path', '')
            try:
                with open(path, 'r') as f:
                    content = f.read()
            except Exception as e:
                content = str(e)
            
            return {
                'jsonrpc': '2.0',
                'id': req_id,
                'result': {
                    'content': [{'type': 'text', 'text': content}]
                }
            }
    
    elif method == 'resources/list':
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
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")
            sys.stderr.flush()

if __name__ == '__main__':
    main()
