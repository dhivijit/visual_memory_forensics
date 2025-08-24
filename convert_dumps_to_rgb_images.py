import os
import numpy as np
import cv2
from math import ceil
import csv
try:
    from tqdm import tqdm
    USE_TQDM = True
except Exception:
    USE_TQDM = False

# === CONFIG ===
DUMP_FOLDER = "memory_dumps"
OUTPUT_FOLDER = "memory_images"
IMAGE_WIDTH = 2048
IMAGE_HEIGHT = 2048
METADATA_FILE = "forensics_out/dump_manifest.csv"
LABEL_COLUMN = 'Label'  # Optional: manually labeled beforehand

os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def convert_to_rgb_image(data_bytes, image_name, output_dir):
    """Split data_bytes into one or more RGB images and save into output_dir.

    Returns a list of dicts: {'path': path, 'start': start_byte, 'end': end_byte, 'size': bytes_in_image}
    """
    # Each image holds this many bytes
    img_area = IMAGE_WIDTH * IMAGE_HEIGHT
    bytes_per_image = img_area * 3

    os.makedirs(output_dir, exist_ok=True)

    mappings = []
    total_len = len(data_bytes)
    # determine number of chunks (at least 1 so empty files produce one image)
    chunk_count = max(1, int(ceil(total_len / bytes_per_image))) if total_len > 0 else 1

    iterator = range(chunk_count)
    if USE_TQDM:
        iterator = tqdm(iterator, desc=f"{image_name}", unit="img")

    for serial_idx in iterator:
        offset = serial_idx * bytes_per_image
        chunk = data_bytes[offset: offset + bytes_per_image]

        # If chunk is shorter than needed, pad to multiple of 3
        if len(chunk) % 3 != 0:
            pad_len = 3 - (len(chunk) % 3)
            chunk += b'\x00' * pad_len

        pixel_count = len(chunk) // 3
        rgb_array = np.frombuffer(chunk, dtype=np.uint8).reshape((pixel_count, 3))

        if pixel_count < img_area:
            pad = np.zeros((img_area - pixel_count, 3), dtype=np.uint8)
            rgb_array = np.vstack((rgb_array, pad))
        elif pixel_count > img_area:
            rgb_array = rgb_array[:img_area]

        image = rgb_array.reshape((IMAGE_HEIGHT, IMAGE_WIDTH, 3))

        # Append serial to filename before extension
        base, ext = os.path.splitext(image_name)
        seq_name = f"{base}_{serial_idx+1}{ext}"
        image_path = os.path.join(output_dir, seq_name)
        cv2.imwrite(image_path, image)

        # compute byte range from original data
        if total_len == 0:
            start = 0
            end = 0
            size_included = 0
        else:
            start = offset
            end = min(offset + bytes_per_image, total_len) - 1
            size_included = end - start + 1

        mappings.append({'path': image_path, 'start': start, 'end': end, 'size': size_included})

    return mappings

def process_all_dumps():
    # Try reading metadata/manifest
    if not os.path.isfile(METADATA_FILE):
        print(f"Metadata file not found: {METADATA_FILE}")
        return

    with open(METADATA_FILE, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # If manifest includes a 'dump_dir' column (forensics output), prefer that
            dump_dir = row.get('dump_dir') or row.get('DumpDir') or row.get('DUMP_DIR')
            if dump_dir:
                # candidate locations where the dump folder may exist
                candidates = [os.path.join('forensics_out', dump_dir), os.path.join('forensics_out', 'dumps', dump_dir)]
                found = False
                for cand in candidates:
                    if os.path.isdir(cand):
                        # look for a .dmp file directly in this folder
                        for fname in os.listdir(cand):
                            if fname.lower().endswith('.dmp'):
                                dmp_path = os.path.join(cand, fname)
                                images_dir = os.path.join(cand, 'images')
                                os.makedirs(images_dir, exist_ok=True)
                                label = row.get('name', row.get('Name', 'unknown'))
                                print(f"Processing manifest entry: {dmp_path} -> {images_dir}")
                                with open(dmp_path, 'rb') as f:
                                    data = f.read()
                                base_name = os.path.splitext(fname)[0]
                                image_name = f"{base_name}_{label}.png"
                                mappings = convert_to_rgb_image(data, image_name, images_dir)
                                # write index
                                index_path = os.path.join(images_dir, f"{base_name}_index.csv")
                                with open(index_path, 'w', newline='') as idxf:
                                    w = csv.DictWriter(idxf, fieldnames=['image', 'start_byte', 'end_byte', 'size_bytes'])
                                    w.writeheader()
                                    for m in mappings:
                                        w.writerow({'image': os.path.basename(m['path']), 'start_byte': m['start'], 'end_byte': m['end'], 'size_bytes': m['size']})
                                print(f"✅ Converted: {dmp_path} → {len(mappings)} images in {images_dir}")
                                found = True
                                break
                        if found:
                            break
                if not found:
                    print(f"❌ No .dmp found for manifest dump_dir '{dump_dir}' in candidate locations: {candidates}")
                continue

            # Fallback: expect original format with 'DumpFilename' referring to files under DUMP_FOLDER
            dump_filename = row.get('DumpFilename') or row.get('dumpfilename')
            if dump_filename:
                dump_path = os.path.join(DUMP_FOLDER, dump_filename)
                label = row.get(LABEL_COLUMN, 'unknown')
                if not os.path.isfile(dump_path):
                    print(f"❌ File not found: {dump_path}")
                    continue
                with open(dump_path, 'rb') as f:
                    data = f.read()
                base_name = os.path.splitext(dump_filename)[0]
                dump_folder = os.path.join(OUTPUT_FOLDER, base_name)
                os.makedirs(dump_folder, exist_ok=True)
                image_name = f"{base_name}_{label}.png"
                mappings = convert_to_rgb_image(data, image_name, dump_folder)
                index_path = os.path.join(dump_folder, f"{base_name}_index.csv")
                with open(index_path, 'w', newline='') as idxf:
                    w = csv.DictWriter(idxf, fieldnames=['image', 'start_byte', 'end_byte', 'size_bytes'])
                    w.writeheader()
                    for m in mappings:
                        w.writerow({'image': os.path.basename(m['path']), 'start_byte': m['start'], 'end_byte': m['end'], 'size_bytes': m['size']})
                print(f"✅ Converted: {dump_path} → {len(mappings)} images in {dump_folder}")
            else:
                print(f"⚠️  Unrecognized metadata row (no dump_dir or DumpFilename): {row}")

if __name__ == "__main__":
    process_all_dumps()
