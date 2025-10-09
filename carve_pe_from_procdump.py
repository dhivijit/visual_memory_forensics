#!/usr/bin/env python3
"""
carve_pe_from_procdump.py

Usage:
    python3 carve_pe_from_procdump.py <process_dump> [output_folder]

If no output folder is provided, you'll be prompted to enter one interactively.

This script:
  - Scans a Windows process dump for PE files (headers starting with MZ)
  - Validates each with pefile
  - Extracts and writes valid (and partial) PEs into the chosen folder
  - Produces a carved_pe/index.json summary file
"""

import sys, os, mmap, struct, json
from pathlib import Path
import pefile

def get_output_folder():
    """Interactive prompt for output folder if not provided."""
    folder = input("Enter output folder name (default: carved_pe): ").strip()
    if not folder:
        folder = "carved_pe"
    return Path(folder)

def carve_pes(dump_path, out_dir):
    size = os.path.getsize(dump_path)
    with open(dump_path, "rb") as f:
        m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        results = []
        count = 0
        offset = 0
        MAX_CANDIDATES = 10000

        print(f"\n[+] Scanning {dump_path} ({size/1024/1024:.1f} MB)...\n")

        while True:
            pos = m.find(b"MZ", offset)
            if pos == -1:
                break
            try:
                if pos + 0x40 > size:
                    offset = pos + 2
                    continue

                e_lfanew = struct.unpack_from("<I", m, pos + 0x3C)[0]
                pe_offset = pos + e_lfanew
                if pe_offset + 4 > size or m[pe_offset:pe_offset+4] != b"PE\x00\x00":
                    offset = pos + 2
                    continue

                num_sections = struct.unpack_from("<H", m, pe_offset + 6)[0]
                size_opt_hdr = struct.unpack_from("<H", m, pe_offset + 0x14)[0]
                magic = struct.unpack_from("<H", m, pe_offset + 0x18)[0]

                if magic not in (0x10b, 0x20b):  # PE32 / PE32+
                    offset = pos + 2
                    continue

                header_end = min(pe_offset + 0x18 + size_opt_hdr + num_sections * 0x28, size)
                slice_bytes = m[pos:header_end]

                try:
                    pe = pefile.PE(data=slice_bytes, fast_load=True)
                except pefile.PEFormatError:
                    offset = pos + 2
                    continue

                # Compute full image size
                try:
                    image_size = int(pe.OPTIONAL_HEADER.SizeOfImage)
                except Exception:
                    image_size = 0

                largest = 0
                for s in pe.sections:
                    end_v = s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
                    largest = max(largest, end_v)
                if image_size < largest:
                    image_size = largest

                candidate_size = min(image_size or 0x400000, size - pos)
                blob = m[pos:pos + candidate_size]

                valid = False
                try:
                    pefile.PE(data=blob)
                    valid = True
                except Exception:
                    pass

                out_name = out_dir / f"carved_{count:04d}.bin"
                with open(out_name, "wb") as out_f:
                    out_f.write(blob)

                results.append({
                    "index": count,
                    "offset": pos,
                    "size": len(blob),
                    "parsed": valid,
                    "magic": hex(magic),
                    "sections": num_sections
                })

                print(f"[{'OK' if valid else '??'}] {out_name.name} @ {pos} size={len(blob)} parsed={valid}")
                count += 1

                if count >= MAX_CANDIDATES:
                    print("Reached max candidates — stopping.")
                    break

                offset = pos + 2

            except Exception as e:
                print(f"[!] Error at {pos}: {e}")
                offset = pos + 2
                continue

        # Save summary
        index_path = out_dir / "index.json"
        with open(index_path, "w") as jf:
            json.dump(results, jf, indent=2)

        print(f"\n[✓] Done. Carved {len(results)} candidates into: {out_dir}\nSummary: {index_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 carve_pe_from_procdump.py <process_dump> [output_folder]")
        sys.exit(1)

    dump_path = Path(sys.argv[1])
    if not dump_path.exists():
        print(f"Error: file not found — {dump_path}")
        sys.exit(1)

    if len(sys.argv) >= 3:
        out_dir = Path(sys.argv[2])
    else:
        out_dir = get_output_folder()

    out_dir.mkdir(parents=True, exist_ok=True)
    carve_pes(dump_path, out_dir)
