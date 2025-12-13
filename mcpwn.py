#!/usr/bin/env python3
"""Mcpwn - MCP Security Testing Framework"""
import argparse
import logging
import sys
from core import MCPPentester

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)


def main():
    parser = argparse.ArgumentParser(
        description='MCP Security Testing Framework'
    )
    parser.add_argument('--safe-mode', action='store_true',
                        help='Skip destructive tests')
    parser.add_argument('--tags', nargs='+',
                        help='Only run specific test tags')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds')
    parser.add_argument('--parallel', action='store_true',
                        help='Use parallel flooding')
    parser.add_argument('--output-json', type=str,
                        help='Export findings as JSON')
    parser.add_argument('--output-html', type=str,
                        help='Export findings as HTML')
    parser.add_argument('--output-sarif', type=str,
                        help='Export findings as SARIF (for CI/CD)')
    parser.add_argument('--rce-only', action='store_true',
                        help='Focus on RCE detection only (fast)')
    parser.add_argument('--quick', action='store_true',
                        help='Quick scan with minimal payloads')
    parser.add_argument('--llm-generate', action='store_true',
                        help='Enable LLM-guided payload generation')
    parser.add_argument('--api-key', type=str,
                        help='API key for LLM (or set ANTHROPIC_API_KEY/GEMINI_API_KEY env var)')
    parser.add_argument('server_cmd', nargs=argparse.REMAINDER,
                        help='MCP server command')

    args = parser.parse_args()

    logger = logging.getLogger('mcpwn')
    
    if not args.server_cmd:
        logger.error("Error: MCP server command required")
        parser.print_help()
        return 1
    
    if args.timeout <= 0:
        logger.error("Timeout must be positive")
        return 1

    try:
        import os
        api_key = args.api_key or os.getenv('ANTHROPIC_API_KEY') or os.getenv('GEMINI_API_KEY') or os.getenv('OPENROUTER_API_KEY')
        
        if args.llm_generate and not api_key:
            logger.warning("--llm-generate enabled but no API key provided. Set --api-key or ANTHROPIC_API_KEY/GEMINI_API_KEY/OPENROUTER_API_KEY env var")
        
        timeout = 5 if args.quick else args.timeout
        
        pentester = MCPPentester(args.server_cmd, config={
            'safe_mode': args.safe_mode,
            'tags': args.tags,
            'timeout': timeout,
            'parallel': args.parallel,
            'output_json': args.output_json,
            'output_html': args.output_html,
            'output_sarif': args.output_sarif,
            'rce_only': args.rce_only,
            'quick': args.quick,
            'generation_mode': args.llm_generate,
            'api_key': api_key
        })
        pentester.run()
    except Exception as e:
        logger.critical("Fatal error: %s", e, exc_info=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
