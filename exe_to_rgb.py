import os
import sys
import numpy as np
import cv2
from math import ceil

try:
    from tqdm import tqdm
    USE_TQDM = True
except Exception:
    USE_TQDM = False

# === CONFIG ===
IMAGE_WIDTH = 2048
IMAGE_HEIGHT = 2048
OUTPUT_FOLDER = "exe_images"

os.makedirs(OUTPUT_FOLDER, exist_ok=True)


def convert_to_rgb_image(data_bytes, image_name, output_dir):
    """Split EXE bytes into one or more RGB images and save into output_dir.

    Returns a list of dicts: {'path': path, 'start': start_byte, 'end': end_byte, 'size': bytes_in_image}
    """
    img_area = IMAGE_WIDTH * IMAGE_HEIGHT
    bytes_per_image = img_area * 3

    os.makedirs(output_dir, exist_ok=True)

    mappings = []
    total_len = len(data_bytes)
    chunk_count = max(1, int(ceil(total_len / bytes_per_image))) if total_len > 0 else 1

    iterator = range(chunk_count)
    if USE_TQDM:
        iterator = tqdm(iterator, desc=f"{image_name}", unit="img")

    for serial_idx in iterator:
        offset = serial_idx * bytes_per_image
        chunk = data_bytes[offset: offset + bytes_per_image]

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

        base, ext = os.path.splitext(image_name)
        seq_name = f"{base}_{serial_idx+1}.png"
        image_path = os.path.join(output_dir, seq_name)
        cv2.imwrite(image_path, image)

        start = offset
        end = min(offset + bytes_per_image, total_len) - 1
        size_included = end - start + 1 if total_len > 0 else 0

        mappings.append({'path': image_path, 'start': start, 'end': end, 'size': size_included})

    return mappings


def process_exe(exe_path):
    if not os.path.isfile(exe_path):
        print(f"❌ File not found: {exe_path}")
        return

    base_name = os.path.basename(exe_path)
    name_noext = os.path.splitext(base_name)[0]
    output_dir = os.path.join(OUTPUT_FOLDER, name_noext)
    os.makedirs(output_dir, exist_ok=True)

    print(f"🔍 Reading: {exe_path}")
    with open(exe_path, 'rb') as f:
        data = f.read()

    print(f"🖼️  Converting {len(data)} bytes from {base_name} → RGB images ...")
    mappings = convert_to_rgb_image(data, base_name, output_dir)
    print(f"✅ Done: {len(mappings)} image(s) saved to {output_dir}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python exe_to_rgb.py <file.exe>")
        sys.exit(1)

    exe_path = sys.argv[1]
    process_exe(exe_path)
    