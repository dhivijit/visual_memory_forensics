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
import traceback
import struct
import re

def extract_imports_from_pe(path, main_only=False, resolve_ordinals=False):
    """Return DLL → list of imported functions for a PE file"""
    # pefile can raise a variety of exceptions (including AttributeError in
    # some corrupted/debug-directory cases). Guard broadly and try a
    # fallback with fast_load to avoid crashing the whole script.
    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as e:
        # Try a more forgiving fast_load parse; if that fails, skip file.
        try:
            pe = pefile.PE(path, fast_load=True)
            # Attempt to lazily parse directories (best-effort). If this
            # raises, we'll still continue and just extract what we can.
            try:
                pe.parse_data_directories()
            except Exception:
                # ignore parse errors from specific directories
                pass
        except Exception as e2:
            print(f"[!] Error parsing {os.path.basename(path)}: {e2}")
            # optional debug output; uncomment if you need a traceback
            # traceback.print_exc()
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

    # If pefile didn't find any imports, attempt a best-effort heuristic
    # scan: look for DLL name strings in .rdata/.data and nearby function names.
    if not info["imports"]:
        try:
            data = pe.__data__
            # gather candidate sections (.rdata/.data/.rsrc/.text) raw ranges
            ranges = []
            for s in pe.sections:
                name = s.Name.decode(errors="ignore").rstrip('\x00')
                if name.lower() in ('.rdata', '.data', '.rsrc', '.text'):
                    ranges.append((s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData, s.VirtualAddress))

            # search for dll-like names (with or without .dll extension), case-insensitive
            dll_regex = re.compile(rb"[A-Za-z0-9_\-\.]{3,40}(?:\\.(?:dll))?", re.IGNORECASE)
            found = {}
            for start, end, va in ranges:
                seg = data[start:end]
                for m in dll_regex.finditer(seg):
                    raw_name_off = start + m.start()
                    name = m.group(0).decode(errors='ignore')
                    # attempt to find nearby ascii function names (NULL-terminated)
                    funcs = []
                    scan_from = max(start, raw_name_off - 256)
                    scan_to = min(end, raw_name_off + 1024)
                    window = data[scan_from:scan_to]
                    # crude heuristic: find printable sequences ending with \x00 that look like function names
                    for fn in re.finditer(rb"([A-Za-z_][A-Za-z0-9_]{2,80})\\x00", window):
                        name_raw_off = scan_from + fn.start()
                        # skip the dll name itself
                        if name_raw_off == raw_name_off:
                            continue
                        funcs.append(fn.group(1).decode(errors='ignore'))
                    if funcs:
                        found[name] = list(dict.fromkeys(funcs))[:50]

            # attach heuristic findings if any
            if found:
                info['imports'] = found
            else:
                # Try a more accurate manual parse of the Import Directory using RVAs
                try:
                    imp_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
                    imp_rva = int(imp_dir.VirtualAddress)
                    imp_size = int(imp_dir.Size)
                    if imp_rva:
                        try:
                            imp_raw = pe.get_offset_from_rva(imp_rva)
                        except Exception:
                            imp_raw = None
                        if imp_raw and imp_raw < len(data):
                            off = imp_raw
                            is64 = pe.OPTIONAL_HEADER.Magic == 0x20B
                            thunk_size = 8 if is64 else 4
                            while off + 20 <= len(data):
                                try:
                                    orig_first_thunk, time_date_stamp, forwarder_chain, name_rva, first_thunk = struct.unpack_from('<LLLLL', data, off)
                                except struct.error:
                                    break
                                # terminator
                                if orig_first_thunk == 0 and time_date_stamp == 0 and forwarder_chain == 0 and name_rva == 0 and first_thunk == 0:
                                    break
                                # resolve DLL name
                                dll_name = None
                                try:
                                    name_raw = pe.get_offset_from_rva(name_rva)
                                    # read null-terminated
                                    end = data.find(b'\x00', name_raw)
                                    if end != -1:
                                        dll_name = data[name_raw:end].decode(errors='ignore')
                                except Exception:
                                    dll_name = None

                                if not dll_name:
                                    off += 20
                                    continue

                                # parse thunk table
                                thunk_rva = orig_first_thunk or first_thunk
                                funcs = []
                                try:
                                    thunk_raw = pe.get_offset_from_rva(thunk_rva)
                                except Exception:
                                    thunk_raw = None

                                if thunk_raw and thunk_raw < len(data):
                                    idx = thunk_raw
                                    while idx + thunk_size <= len(data):
                                        if thunk_size == 8:
                                            val = struct.unpack_from('<Q', data, idx)[0]
                                            if val == 0:
                                                break
                                            # IMAGE_ORDINAL_FLAG64
                                            if (val & 0x8000000000000000) != 0:
                                                ordinal = val & 0xffff
                                                funcs.append(f"ordinal_{ordinal}")
                                            else:
                                                hint_name_rva = val & 0xffffffff
                                                try:
                                                    hn_raw = pe.get_offset_from_rva(hint_name_rva)
                                                    if hn_raw + 2 < len(data):
                                                        # skip hint
                                                        i = hn_raw + 2
                                                        end = data.find(b'\x00', i)
                                                        if end != -1:
                                                            funcs.append(data[i:end].decode(errors='ignore'))
                                                except Exception:
                                                    pass
                                        else:
                                            val = struct.unpack_from('<L', data, idx)[0]
                                            if val == 0:
                                                break
                                            # IMAGE_ORDINAL_FLAG32
                                            if (val & 0x80000000) != 0:
                                                ordinal = val & 0xffff
                                                funcs.append(f"ordinal_{ordinal}")
                                            else:
                                                hint_name_rva = val & 0xffffffff
                                                try:
                                                    hn_raw = pe.get_offset_from_rva(hint_name_rva)
                                                    if hn_raw + 2 < len(data):
                                                        i = hn_raw + 2
                                                        end = data.find(b'\x00', i)
                                                        if end != -1:
                                                            funcs.append(data[i:end].decode(errors='ignore'))
                                                except Exception:
                                                    pass
                                        idx += thunk_size

                                info['imports'][dll_name] = funcs
                                off += 20
                except Exception:
                    pass
        except Exception:
            # if any heuristic step fails, ignore and leave imports empty
            pass

    # detect if this binary likely resolves imports dynamically
    for dll, funcs in info["imports"].items():
        for fn in funcs:
            if fn.lower().startswith("getprocaddress") or fn.lower().startswith("loadlibrary"):
                info["dynamic_resolution_suspected"] = True

    # If requested, filter to main DLLs and optionally resolve ordinals
    if main_only or resolve_ordinals:
        MAIN_DLLS = {
            'kernel32.dll','ntdll.dll','advapi32.dll','user32.dll','ws2_32.dll',
            'iphlpapi.dll','crypt32.dll','userenv.dll','psapi.dll','gdi32.dll',
            'ole32.dll','shell32.dll','msvcrt.dll','bcrypt.dll','secur32.dll',
            'shlwapi.dll'
        }

        # make mapping case-insensitive
        new_imports = {}

        def find_system_dll(dll_name):
            # ensure extension
            name = dll_name if dll_name.lower().endswith('.dll') else dll_name + '.dll'
            locations = []
            sysroot = os.environ.get('SystemRoot') or os.environ.get('WINDIR')
            if sysroot:
                locations.append(os.path.join(sysroot, 'System32', name))
                locations.append(os.path.join(sysroot, 'SysWOW64', name))
                locations.append(os.path.join(sysroot, 'System32', 'drivers', name))
            # PATH search
            for p in os.environ.get('PATH', '').split(os.pathsep):
                locations.append(os.path.join(p, name))
            # dedupe
            seen = set()
            for p in locations:
                if p in seen:
                    continue
                seen.add(p)
                if os.path.exists(p):
                    return p
            return None

        def build_export_map(dll_path):
            try:
                pe_d = pefile.PE(dll_path)
                if not hasattr(pe_d, 'DIRECTORY_ENTRY_EXPORT'):
                    return {}
                emap = {}
                for sym in pe_d.DIRECTORY_ENTRY_EXPORT.symbols:
                    # sym.ordinal, sym.name
                    if sym.name:
                        try:
                            emap[int(sym.ordinal)] = sym.name.decode(errors='ignore')
                        except Exception:
                            emap[int(sym.ordinal)] = sym.name
                return emap
            except Exception:
                return {}

        # Pre-cache export maps for found system DLLs
        export_cache = {}

        for dll, funcs in list(info['imports'].items()):
            dll_l = dll.lower()
            # normalize to include .dll for matching/cache keys
            dll_norm = dll_l if dll_l.endswith('.dll') else dll_l + '.dll'
            if main_only and dll_norm not in MAIN_DLLS:
                continue

            out_funcs = []
            for fn in funcs:
                m = re.match(r'^ordinal_(\d+)$', fn)
                if m and resolve_ordinals:
                    ordn = int(m.group(1))
                    # find system dll path (cache)
                    if dll_norm not in export_cache:
                        dll_path = find_system_dll(dll_norm)
                        export_cache[dll_norm] = build_export_map(dll_path) if dll_path else {}
                    name_map = export_cache[dll_norm]
                    resolved = name_map.get(ordn)
                    if resolved:
                        out_funcs.append(resolved)
                    else:
                        out_funcs.append(fn)
                else:
                    out_funcs.append(fn)

            if out_funcs:
                # store normalized dll name
                new_imports[dll_norm] = list(dict.fromkeys(out_funcs))

        if main_only:
            info['imports'] = new_imports
        else:
            # merge resolved ordinals back into imports while keeping others
            for dll, funcs in new_imports.items():
                info['imports'][dll] = funcs

    return info


def main():
    parser = argparse.ArgumentParser(description="Extract DLL/API imports from carved PE .bin files.")
    parser.add_argument("--input", "-i", required=True, help="Folder containing carved .bin files")
    parser.add_argument("--output", "-o", default="imports.json", help="Output JSON file")
    parser.add_argument("--main-only", action='store_true', help="Only keep a curated set of main system DLLs in the report")
    parser.add_argument("--resolve-ordinals", action='store_true', help="Attempt to resolve ordinal_N entries using system DLL exports")
    args = parser.parse_args()

    input_dir = Path(args.input)
    output = Path(args.output)

    all_entries = []
    for f in sorted(input_dir.glob("*.bin")):
        info = extract_imports_from_pe(f, main_only=args.main_only, resolve_ordinals=args.resolve_ordinals)
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
