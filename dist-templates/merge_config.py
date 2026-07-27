#!/usr/bin/env python3
"""Produce a merged config candidate for `upgrade.sh`.

Reads the operator's live config.yaml and the new version's example config,
then writes a candidate that keeps every existing value, comment, and bit of
formatting from the live file while inserting only the key-paths that are new
in this version (each with the example's comment). The live file is never
modified — upgrade.sh writes the result to config.yaml.upgraded for the
operator to review and adopt.

Uses ruamel.yaml round-trip mode so comments/quoting/order survive the merge.
ruamel is a hard requirement: exit 3 if it is unavailable (upgrade.sh treats
that as fatal rather than silently degrading).

Usage:
    merge_config.py <live_config.yaml> <new_example.yaml> <output_candidate.yaml>

Exit codes:
    0  merge written (added key-paths, if any, printed one per line to stdout)
    2  bad arguments / unreadable input
    3  ruamel.yaml not available
"""
import sys


def _fail(msg, code):
    sys.stderr.write(msg + "\n")
    sys.exit(code)


def main(live_path, example_path, out_path):
    try:
        from ruamel.yaml import YAML
    except ImportError:
        _fail("ERROR: ruamel.yaml is required for the config merge but is not "
              "installed. Ensure the bundle's ruamel wheel was installed.", 3)

    yaml = YAML()  # round-trip by default: preserves comments, order, quoting
    yaml.preserve_quotes = True

    try:
        with open(live_path, encoding="utf-8") as f:
            live = yaml.load(f)
    except Exception as e:  # pylint: disable=broad-exception-caught
        _fail(f"ERROR: cannot read live config {live_path}: {e}", 2)
    try:
        with open(example_path, encoding="utf-8") as f:
            example = yaml.load(f)
    except Exception as e:  # pylint: disable=broad-exception-caught
        _fail(f"ERROR: cannot read new example {example_path}: {e}", 2)

    if live is None:
        live = example.__class__()  # empty CommentedMap of the same type

    added = []

    def merge(dst, src, prefix):
        """Insert keys present in src (example) but missing in dst (live).

        Recurses into mappings that exist on both sides so nested new keys are
        placed under their correct parent. Never overwrites an existing value.
        """
        # Only mapping-vs-mapping merges make sense; anything else is left as-is.
        if not hasattr(src, "keys"):
            return
        for key in src.keys():
            path = f"{prefix}.{key}" if prefix else str(key)
            if hasattr(dst, "keys") and key in dst:
                # Present on both sides — recurse if both are mappings.
                if hasattr(src[key], "keys") and hasattr(dst[key], "keys"):
                    merge(dst[key], src[key], path)
                # Otherwise keep the live scalar/list untouched.
            else:
                # Missing in live — insert value + carry over its comment.
                dst[key] = src[key]
                _copy_comment(dst, src, key)
                added.append(path)

    def _copy_comment(dst, src, key):
        """Best-effort copy of the comment attached to `key` from src to dst."""
        try:
            src_ca = src.ca.items.get(key)
            if src_ca is not None:
                dst.ca.items[key] = src_ca
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # comments are advisory; never fail the merge over them

    merge(live, example, "")

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            yaml.dump(live, f)
    except Exception as e:  # pylint: disable=broad-exception-caught
        _fail(f"ERROR: cannot write merged candidate {out_path}: {e}", 2)

    for path in added:
        print(path)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        _fail("usage: merge_config.py <live_config.yaml> <new_example.yaml> "
              "<output_candidate.yaml>", 2)
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))
