#!/usr/bin/env python3
"""
fix_liquid_raw.py

Protege contenido que contiene '{{', '}}', '{%' o '%}' dentro de:
 - bloques de código fence (```...```)
 - líneas sueltas (agrupadas contiguamente)

Evita tocar el front-matter YAML (--- ... ---) y respeta bloques ya envueltos por
{% raw %} ... {% endraw %}.

Uso:
  # dry-run (no modifica archivos)
  python3 fix_liquid_raw.py --path _posts --dry-run

  # aplicar cambios (crea copia <file>.orig)
  python3 fix_liquid_raw.py --path _posts

  # procesar recursivamente todo el repo
  python3 fix_liquid_raw.py --path . --recursive
"""
from pathlib import Path
import argparse
import shutil
import sys

LIQUID_TOKENS = ("{{", "}}", "{%", "%}")

def file_should_process(p: Path, exts=(".md", ".markdown")):
    return p.is_file() and p.suffix.lower() in exts

def contains_token_in_lines(lines):
    for l in lines:
        for t in LIQUID_TOKENS:
            if t in l:
                return True
    return False

def process_file(path: Path):
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    n = len(lines)
    if n == 0:
        return False, ""

    out_lines = []
    i = 0

    # detect front-matter (only at top)
    in_front_matter = False
    if lines[0].strip() == '---':
        in_front_matter = True
        out_lines.append(lines[0])
        i = 1
        while i < n:
            out_lines.append(lines[i])
            if lines[i].strip() == '---':
                i += 1
                in_front_matter = False
                break
            i += 1

    in_raw = False

    while i < n:
        line = lines[i]

        # handle explicit raw blocks - respect them
        stripped = line.strip()
        if stripped.startswith('{% raw %}'):
            in_raw = True
            out_lines.append(line)
            i += 1
            continue
        if stripped.startswith('{% endraw %}'):
            in_raw = False
            out_lines.append(line)
            i += 1
            continue

        if in_raw:
            out_lines.append(line)
            i += 1
            continue

        # fenced code block processing
        if line.startswith('```'):
            fence_start_idx = i
            fence_block = [lines[i]]
            i += 1
            # collect until closing fence or EOF
            while i < n and not lines[i].startswith('```'):
                fence_block.append(lines[i])
                i += 1
            # include closing fence if present
            if i < n:
                fence_block.append(lines[i])
                i += 1

            # if block contains Liquid tokens, wrap the whole fence with raw
            if contains_token_in_lines(fence_block):
                out_lines.append('{% raw %}\n')
                out_lines.extend(fence_block)
                # ensure newline before endraw if last fence line didn't end with newline
                if not fence_block[-1].endswith("\n"):
                    out_lines.append("\n")
                out_lines.append('{% endraw %}\n')
            else:
                out_lines.extend(fence_block)
            continue

        # non-fenced lines: group contiguous lines that contain tokens
        if any(tok in line for tok in LIQUID_TOKENS):
            start = i
            group = []
            while i < n and any(tok in lines[i] for tok in LIQUID_TOKENS):
                group.append(lines[i])
                i += 1
            # wrap group with raw
            out_lines.append('{% raw %}\n')
            out_lines.extend(group)
            # ensure newline before endraw
            if not group[-1].endswith("\n"):
                out_lines.append("\n")
            out_lines.append('{% endraw %}\n')
            continue

        # otherwise just copy line
        out_lines.append(line)
        i += 1

    new_text = "".join(out_lines)

    # If nothing changed, return False
    if new_text == text:
        return False, text
    return True, new_text

def main():
    parser = argparse.ArgumentParser(description="Wrap Liquid-like constructs with {% raw %}...{% endraw %} in Markdown files.")
    parser.add_argument("--path", "-p", default="_posts", help="Path to directory or file to process (default: _posts)")
    parser.add_argument("--recursive", "-r", action="store_true", help="Recursively search directories")
    parser.add_argument("--dry-run", action="store_true", help="Don't modify files; just print which would change")
    parser.add_argument("--backup", action="store_true", help="Make a .orig backup of modified files (default: True when not dry-run)")
    args = parser.parse_args()

    root = Path(args.path)
    if not root.exists():
        print("Path not found:", root)
        sys.exit(1)

    files = []
    if root.is_file():
        if file_should_process(root):
            files = [root]
    else:
        if args.recursive:
            files = [p for p in root.rglob("*") if file_should_process(p)]
        else:
            files = [p for p in root.iterdir() if file_should_process(p)]

    if not files:
        print("No markdown files found to process under", root)
        return

    changed = []
    for f in sorted(files):
        ok, new_text = process_file(f)
        if ok:
            changed.append(f)
            print("Will modify:", f)
            if not args.dry_run:
                # backup
                bak = f.with_suffix(f.suffix + ".orig")
                try:
                    if args.backup or True:
                        if not bak.exists():
                            shutil.copy2(f, bak)
                except Exception as e:
                    print("Warning: couldn't create backup for", f, ":", e)
                # write file
                f.write_text(new_text, encoding="utf-8")
        else:
            print("No change:", f)

    print()
    print(f"Processed {len(files)} files. Modified: {len(changed)}")
    if args.dry_run:
        print("dry-run enabled, no files were changed. Remove --dry-run to apply changes.")
    else:
        if changed:
            print("Backups made with .orig suffix where applicable.")
        else:
            print("No modifications necessary.")

if __name__ == "__main__":
    main()