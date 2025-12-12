"""Mcpwn - MCP Security Testing Framework"""
import argparse
import shlex
from core import MCPPentester


def main():
    parser = argparse.ArgumentParser(
        description='MCP Security Testing Framework'
    )
    parser.add_argument('server_cmd', nargs='+',
                        help='MCP server command')
    parser.add_argument('--safe-mode', action='store_true',
                        help='Skip destructive tests')
    parser.add_argument('--tags', nargs='+',
                        help='Only run specific test tags')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Request timeout in seconds')
    parser.add_argument('--parallel', action='store_true',
                        help='Use parallel flooding')
    parser.add_argument('--output-json', type=str,
                        help='Export findings as JSON')
    parser.add_argument('--output-html', type=str,
                        help='Export findings as HTML')
    parser.add_argument('--rce-only', action='store_true',
                        help='Focus on RCE detection only (fast)')
    parser.add_argument('--quick', action='store_true',
                        help='Quick scan with minimal payloads')

    try:
        args = parser.parse_args()
    except SystemExit:
        return 1

    if args.timeout <= 0:
        print("[!] Error: timeout must be positive")
        return 1

    try:
        pentester = MCPPentester(args.server_cmd, config={
            'safe_mode': args.safe_mode,
            'tags': args.tags,
            'timeout': args.timeout,
            'parallel': args.parallel,
            'output_json': args.output_json,
            'output_html': args.output_html,
            'rce_only': args.rce_only,
            'quick': args.quick
        })
        pentester.run()
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    main()
