"""Command-line interface entrypoint for AuthLog Lens."""

import argparse
import sys
import os

from authlog_lens.parser import parse_log_file
from authlog_lens.analyzer import analyze_events
from authlog_lens.reporter import format_terminal, format_json, format_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authlog-lens",
        description="AuthLog Lens: Defensive Linux authentication log analyzer and intrusion detector.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    analyze_cmd = subparsers.add_parser("analyze", help="Analyze an auth log file for attacks and anomalies")
    analyze_cmd.add_argument("logfile", help="Path to auth.log or secure file")
    analyze_cmd.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Report output format (default: text)",
    )
    analyze_cmd.add_argument(
        "--output",
        "-o",
        help="Write output report to file",
    )
    analyze_cmd.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if critical/high threats are detected",
    )
    analyze_cmd.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI terminal colors",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "analyze":
        if not os.path.exists(args.logfile):
            sys.stderr.write(f"Error: Log file not found at '{args.logfile}'\n")
            return 2

        with open(args.logfile, "r", encoding="utf-8", errors="ignore") as f:
            total_lines = sum(1 for _ in f)

        events = parse_log_file(args.logfile)
        report = analyze_events(events, os.path.abspath(args.logfile), total_lines)

        if args.format == "json":
            out = format_json(report)
        elif args.format == "markdown":
            out = format_markdown(report)
        else:
            out = format_terminal(report, use_color=not args.no_color)

        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(out + "\n")
                print(f"Report saved to: {args.output}")
            except Exception as e:
                sys.stderr.write(f"Failed to write output to {args.output}: {e}\n")
                return 1
        else:
            print(out)

        if args.strict and report.has_critical_threats:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
