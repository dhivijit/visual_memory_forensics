#!/usr/bin/env python3
"""
extract_imports_from_bins.py

Usage:
  python3 extract_imports_from_bins.py --input ./carved --output imports.json

Scans each .bin file in the input folder, extracts DLL→API imports,
and writes a JSON report with structure:

{
  "files": [
    {
      "file": "carved_0001.bin",
      "arch": "PE32+",
      "entrypoint": "0x12345",
      "image_base": "0x140000000",
      "imports": {
        "KERNEL32.dll": ["LoadLibraryA", "GetProcAddress", ...],
        "USER32.dll": ["MessageBoxA", ...]
      },
      "dynamic_resolution_suspected": true
    },
    ...
  ]
}
"""

import os, json, argparse
from pathlib import Path
import pefile

def extract_imports_from_pe(path):
    """Return DLL → list of imported functions for a PE file"""
    try:
        pe = pefile.PE(path, fast_load=False)
    except pefile.PEFormatError:
        return None

    info = {
        "file": os.path.basename(path),
        "arch": "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B else "PE32",
        "entrypoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "imports": {},
        "dynamic_resolution_suspected": False,
    }

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode(errors="ignore"))
                elif hasattr(imp, "ordinal"):
                    funcs.append(f"ordinal_{imp.ordinal}")
            info["imports"][dll_name] = funcs

    # detect if this binary likely resolves imports dynamically
    for dll, funcs in info["imports"].items():
        for fn in funcs:
            if fn.lower().startswith("getprocaddress") or fn.lower().startswith("loadlibrary"):
                info["dynamic_resolution_suspected"] = True

    return info


def main():
    parser = argparse.ArgumentParser(description="Extract DLL/API imports from carved PE .bin files.")
    parser.add_argument("--input", "-i", required=True, help="Folder containing carved .bin files")
    parser.add_argument("--output", "-o", default="imports.json", help="Output JSON file")
    args = parser.parse_args()

    input_dir = Path(args.input)
    output = Path(args.output)

    all_entries = []
    for f in sorted(input_dir.glob("*.bin")):
        info = extract_imports_from_pe(f)
        if info:
            print(f"[+] Parsed {f.name} — {len(info['imports'])} DLLs, dynamic={info['dynamic_resolution_suspected']}")
            all_entries.append(info)
        else:
            print(f"[!] Skipped (invalid PE): {f.name}")

    report = {"total": len(all_entries), "files": all_entries}

    with open(output, "w") as jf:
        json.dump(report, jf, indent=2)

    print(f"\n[✓] Done. Results saved to {output} ({len(all_entries)} PEs parsed).")


if __name__ == "__main__":
    main()
