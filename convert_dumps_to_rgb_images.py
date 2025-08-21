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
METADATA_FILE = "dump_metadata.csv"
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
    with open(METADATA_FILE, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            dump_path = os.path.join(DUMP_FOLDER, row['DumpFilename'])
            label = row.get(LABEL_COLUMN, "unknown")
            if not os.path.isfile(dump_path):
                print(f"❌ File not found: {dump_path}")
                continue

            with open(dump_path, 'rb') as f:
                data = f.read()

            base_name = os.path.splitext(row['DumpFilename'])[0]
            # create per-dump subfolder inside OUTPUT_FOLDER for tidiness
            dump_folder = os.path.join(OUTPUT_FOLDER, base_name)
            image_name = f"{base_name}_{label}.png"
            mappings = convert_to_rgb_image(data, image_name, dump_folder)

            # write an index file listing byte ranges
            index_path = os.path.join(dump_folder, f"{base_name}_index.csv")
            with open(index_path, 'w', newline='') as idxf:
                w = csv.DictWriter(idxf, fieldnames=['image', 'start_byte', 'end_byte', 'size_bytes'])
                w.writeheader()
                for m in mappings:
                    w.writerow({'image': os.path.basename(m['path']), 'start_byte': m['start'], 'end_byte': m['end'], 'size_bytes': m['size']})

            # summarise output
            print(f"✅ Converted: {dump_path} → {len(mappings)} images in {dump_folder}")

if __name__ == "__main__":
    process_all_dumps()
