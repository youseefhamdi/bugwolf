# bugwolf/cli/main — top-level parser + entry point
# SCHEMA: bugwolf-cli-main-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .dispatch import SUBCOMMANDS, dispatch

SCHEMA = "bugwolf-cli-main-v1"


def _parent_flags_parser() -> argparse.ArgumentParser:
    """Return a parser that defines the global flags shared by subcommands.

    Used as a ``parents=`` argument so each subparser also accepts
    ``--json``, ``--quiet``, ``--scope-file``, ``--confirm-destructive``,
    and ``--no-color`` without each command having to redeclare them.
    """
    p = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    p.add_argument("--json", action="store_true",
                   help="Emit machine-readable JSON output on stdout.")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress progress output; only print final result.")
    p.add_argument("--scope-file", metavar="PATH", default=None,
                   help="Path to a JSON scope file loaded before any action.")
    p.add_argument("--confirm-destructive", dest="confirm_destructive",
                   action="store_true",
                   help="Required confirmation for destructive actions.")
    p.add_argument("--no-color", action="store_true",
                   help="Plain output (no ANSI color sequences).")
    return p


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level ``bugwolf`` argument parser.

    The parser declares 16 functional subcommands + ``version`` and
    ``help`` (argparse built-ins).  All subcommands share the same
    global flags so downstream handlers can rely on a uniform shape.
    """
    parser = argparse.ArgumentParser(
        prog="bugwolf",
        description="BugWolf unified CLI dispatcher (Phase 5.A).",
        allow_abbrev=False,
    )

    global_flags = parser.add_argument_group("global flags")
    global_flags.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output on stdout.",
    )
    global_flags.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output; only print final result.",
    )
    global_flags.add_argument(
        "--scope-file",
        metavar="PATH",
        default=None,
        help="Path to a JSON scope file loaded before any action runs.",
    )
    global_flags.add_argument(
        "--confirm-destructive",
        action="store_true",
        help="Required confirmation for any subcommand that performs "
             "destructive actions. Subcommands refuse to dispatch without it.",
    )
    global_flags.add_argument(
        "--no-color",
        action="store_true",
        help="Plain output (no ANSI color sequences).",
    )

    subparsers = parser.add_subparsers(
        dest="subcommand",
        metavar="SUBCOMMAND",
        required=False,
    )

    # Lazy import to keep build_parser importable without every command loaded.
    from .commands import (
        discover,
        scan,
        fuzz,
        taint,
        chain,
        audit,
        redteam,
        llm_redteam,
        osint,
        recon,
        report,
        govern,
        semantic,
        regression,
        methodology,
        benchmark,
        distributed,
        version,
    )

    for module in (
        discover,
        scan,
        fuzz,
        taint,
        chain,
        audit,
        redteam,
        llm_redteam,
        osint,
        recon,
        report,
        govern,
        semantic,
        regression,
        methodology,
        benchmark,
        distributed,
        version,
    ):
        name = module.SCHEMA.split("-")[2]
        sub = subparsers.add_parser(
            name.replace("_", "-"),
            help=module.__doc__.strip().splitlines()[0]
            if module.__doc__ else name,
            allow_abbrev=False,
            parents=[_parent_flags_parser()],
        )
        module.add_arguments(sub)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point.

    STUB-SAFE: any unhandled exception is caught and converted into
    exit code 1.  The caller (typically ``python -m bugwolf``) should
    only ever see an integer exit code.
    """
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        if args.subcommand is None:
            parser.print_help(sys.stdout)
            return 0
        return dispatch(args)
    except SystemExit as exc:
        # argparse raises SystemExit on --help / errors; honor it.
        return int(exc.code) if exc.code is not None else 0
    except KeyboardInterrupt:  # noqa: PERF203
        return 130
    except BaseException as exc:  # noqa: BLE001
        # STUB-SAFE: never let the CLI crash the caller.
        print(
            f"bugwolf: unhandled {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
