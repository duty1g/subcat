#!/usr/bin/env python3
"""
Vendor the Wappalyzer technology icon set locally and align it to
``subcat/fingerprints.json`` — the same icon set gowitness uses
(https://github.com/enthec/webappanalyzer, src/images/icons).

What it does:
  1. Sparse-clones the webappanalyzer icons directory (needs git + network),
     unless --src points at an existing local copy.
  2. For every fingerprint with an ``icon`` field, resolves the real file
     (handling .png<->.svg renames and case differences), copies it into
     ``subcat/assets/icons/`` and rewrites the ``icon`` field to the real name.
  3. Clears ``icon`` fields that have no file anywhere (so the JSON never points
     at a missing icon), and prunes orphan local files.
  4. Regenerates ``subcat/ui/data/techIcons.json`` ({name: filename}) for the UI.

Result: fingerprints.json, subcat/assets/icons/ and subcat/ui/data/techIcons.json
are perfectly aligned. Re-run after updating fingerprints.json or webappanalyzer.

Usage:
    python subcat/ui/sync_icons.py [--src PATH_TO_ICONS_DIR]
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

# This script lives at subcat/ui/sync_icons.py.
UI_DIR = os.path.dirname(os.path.abspath(__file__))          # subcat/ui
SUBCAT_DIR = os.path.dirname(UI_DIR)                          # subcat
FINGERPRINTS = os.path.join(SUBCAT_DIR, "fingerprints.json")
ICONS_DST = os.path.join(SUBCAT_DIR, "assets", "icons")
TECH_ICONS_JSON = os.path.join(UI_DIR, "data", "techIcons.json")
REPO = "https://github.com/enthec/webappanalyzer.git"


def sparse_clone() -> str:
    """Shallow sparse-clone just the icons dir; return its path."""
    tmp = tempfile.mkdtemp(prefix="webappanalyzer-")
    print(f"cloning icons into {tmp} ...")
    subprocess.run(
        ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", REPO, tmp],
        check=True,
    )
    subprocess.run(["git", "sparse-checkout", "set", "src/images/icons"], cwd=tmp, check=True)
    return os.path.join(tmp, "src", "images", "icons")


def swap_ext(name: str):
    base, ext = os.path.splitext(name)
    if ext.lower() == ".png":
        return base + ".svg"
    if ext.lower() == ".svg":
        return base + ".png"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", help="existing webappanalyzer icons dir (skips clone)")
    args = ap.parse_args()

    src = args.src or sparse_clone()
    if not os.path.isdir(src):
        sys.exit(f"icons source not found: {src}")

    repo = os.listdir(src)
    ci = {f.lower(): f for f in repo}  # case-insensitive index -> real filename

    def resolve(icon):
        for cand in (icon, swap_ext(icon)):
            if cand and cand.lower() in ci:
                return ci[cand.lower()]
        return None

    with open(FINGERPRINTS, encoding="utf-8") as f:
        data = json.load(f)
    apps = data.get("apps", {})

    if os.path.isdir(ICONS_DST):
        shutil.rmtree(ICONS_DST)
    os.makedirs(ICONS_DST)

    copied, renamed, cleared, missing = set(), 0, 0, []
    for name, v in apps.items():
        icon = v.get("icon")
        if not icon:
            continue
        actual = resolve(icon)
        if actual is None:
            v["icon"] = ""  # no file anywhere -> drop the reference
            cleared += 1
            missing.append(icon)
            continue
        if actual not in copied:
            shutil.copy2(os.path.join(src, actual), os.path.join(ICONS_DST, actual))
            copied.add(actual)
        if actual != icon:
            v["icon"] = actual
            renamed += 1

    # Preserve the original formatting (4-space indent, ascii-escaped).
    with open(FINGERPRINTS, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=4, ensure_ascii=True)
        f.write("\n")

    # UI map: technology name -> icon filename.
    icon_map = {n: v["icon"] for n, v in sorted(apps.items()) if v.get("icon")}
    os.makedirs(os.path.dirname(TECH_ICONS_JSON), exist_ok=True)
    with open(TECH_ICONS_JSON, "w", encoding="utf-8", newline="\n") as f:
        json.dump(icon_map, f, ensure_ascii=False)
        f.write("\n")

    # Verify alignment.
    local = set(os.listdir(ICONS_DST))
    referenced = {v["icon"] for v in apps.values() if v.get("icon")}
    bad = referenced - local
    orphans = local - referenced

    print(f"copied {len(copied)} icons | renamed {renamed} | cleared {cleared} refs")
    print(f"techIcons.json entries: {len(icon_map)}")
    print(f"ALIGNED: {not bad and not orphans} (bad refs={len(bad)}, orphans={len(orphans)})")
    if bad:
        print("  unresolved:", sorted(bad)[:10])


if __name__ == "__main__":
    main()
