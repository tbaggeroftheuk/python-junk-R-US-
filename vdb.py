import numpy as np
import cv2
import os
import argparse
import math
import hashlib
import zlib
import sys
from multiprocessing import Pool, cpu_count
from tqdm import tqdm


try:
    import yt_dlp
except ImportError:
    yt_dlp = None
    print("Warning: yt-dlp not installed. URL download will not work. Install with `pip install yt-dlp`")

cv2.setNumThreads(4)  


FRAME_WIDTH = 1920
FRAME_HEIGHT = 1080
PIXEL_BLOCK_SIZE = 8
FPS = 20

BLOCKS_X = FRAME_WIDTH // PIXEL_BLOCK_SIZE
BLOCKS_Y = FRAME_HEIGHT // PIXEL_BLOCK_SIZE
BITS_PER_FRAME = BLOCKS_X * BLOCKS_Y * 2  # 2 bits per block

MAGIC_HEADER = b'VDB1'


COLOR_BIT_MAP = {
    (255, 255, 255): [0, 0],  # White
    (0, 0, 0):       [0, 1],  # Black
    (0, 255, 0):     [1, 0],  # Green
    (0, 0, 255):     [1, 1],  # Red
}
BIT_COLOR_MAP = {
    (0, 0): (255, 255, 255),
    (0, 1): (0, 0, 0),
    (1, 0): (0, 255, 0),
    (1, 1): (0, 0, 255),
}

def closest_color(rgb):
    def dist(c1, c2):
        return sum((int(a) - int(b)) ** 2 for a, b in zip(c1, c2))
    return min(COLOR_BIT_MAP.keys(), key=lambda c: dist(c, rgb))


def bytes_to_bits(data):
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    bytes_out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        chunk = bits[i:i+8]
        for bit in chunk:
            byte = (byte << 1) | bit
        byte <<= (8 - len(chunk))
        bytes_out.append(byte)
    return bytes_out

def calc_sha256(data):
    sha = hashlib.sha256()
    sha.update(data)
    return sha.digest()

def encode_metadata(filename, original_filesize, compressed_filesize, checksum):
    filename_bytes = filename.encode('utf-8')
    if len(filename_bytes) > 255:
        raise ValueError("Filename too long for metadata")
    meta = bytearray()
    meta.append(len(filename_bytes))
    meta.extend(filename_bytes)
    meta.extend(original_filesize.to_bytes(8, 'big'))
    meta.extend(compressed_filesize.to_bytes(8, 'big'))
    meta.extend(checksum)
    return meta

def decode_metadata(meta_bytes):
    fn_len = meta_bytes[0]
    filename = meta_bytes[1:1+fn_len].decode('utf-8')
    original_filesize = int.from_bytes(meta_bytes[1+fn_len:1+fn_len+8], 'big')
    compressed_filesize = int.from_bytes(meta_bytes[1+fn_len+8:1+fn_len+16], 'big')
    checksum = meta_bytes[1+fn_len+16:1+fn_len+16+32]
    return filename, original_filesize, compressed_filesize, checksum


def bits_to_frame_color(bits):
    frame = np.ones((FRAME_HEIGHT, FRAME_WIDTH, 3), dtype=np.uint8) * 255
    idx = 0
    for by in range(BLOCKS_Y):
        for bx in range(BLOCKS_X):
            if idx >= len(bits):
                break
            b1 = bits[idx] if idx < len(bits) else 0
            b2 = bits[idx + 1] if idx + 1 < len(bits) else 0
            color = BIT_COLOR_MAP[(b1, b2)]
            x = bx * PIXEL_BLOCK_SIZE
            y = by * PIXEL_BLOCK_SIZE
            frame[y:y+PIXEL_BLOCK_SIZE, x:x+PIXEL_BLOCK_SIZE] = color
            idx += 2
    return frame

def frame_to_bits_color(frame):
    bits = []
    for by in range(BLOCKS_Y):
        for bx in range(BLOCKS_X):
            block = frame[by*PIXEL_BLOCK_SIZE:(by+1)*PIXEL_BLOCK_SIZE,
                          bx*PIXEL_BLOCK_SIZE:(bx+1)*PIXEL_BLOCK_SIZE]
            mean_color = tuple(np.mean(block.reshape(-1, 3), axis=0).astype(np.uint8))
            closest = closest_color(mean_color)
            bits.extend(COLOR_BIT_MAP[closest])
    return bits


def encode_file_to_video(input_file, output_file):
    if not (output_file.endswith(".vdb") or output_file.endswith(".mp4")):
        output_file += ".vdb"

    with open(input_file, 'rb') as f:
        data = f.read()

    compressed_data = zlib.compress(data, level=9)
    compressed_size = len(compressed_data)
    filename = os.path.basename(input_file)
    checksum = calc_sha256(compressed_data)

    metadata = encode_metadata(filename, len(data), compressed_size, checksum)

    if output_file.endswith(".vdb"):
        full_data = MAGIC_HEADER + metadata + compressed_data
    else:
        full_data = metadata + compressed_data

    bits = bytes_to_bits(full_data)
    total_frames = math.ceil(len(bits) / BITS_PER_FRAME)

    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    video_out = cv2.VideoWriter(output_file, fourcc, FPS, (FRAME_WIDTH, FRAME_HEIGHT), isColor=True)

    for frame_idx in tqdm(range(total_frames), desc="Encoding frames"):
        start_bit = frame_idx * BITS_PER_FRAME
        end_bit = start_bit + BITS_PER_FRAME
        frame_bits = bits[start_bit:end_bit]
        if len(frame_bits) < BITS_PER_FRAME:
            frame_bits += [0] * (BITS_PER_FRAME - len(frame_bits))

        frame = bits_to_frame_color(frame_bits)
        video_out.write(frame)

    video_out.release()
    print(f"Video saved to {output_file}")

def decode_frame_worker(frame_data):
    return frame_to_bits_color(frame_data)

def decode_video_to_file(input_video, output_folder):
    cap = cv2.VideoCapture(input_video)
    if not cap.isOpened():
        raise IOError(f"Cannot open video file {input_video}")

    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    print(f"Reading {frame_count} frames...")

    all_bits = []
    pool = Pool(processes=max(1, cpu_count() - 1))

    chunk_size = 100
    frames = []
    pbar = tqdm(total=frame_count, desc="Decoding frames")

    def process_chunk(frames_chunk):
        return pool.map(decode_frame_worker, frames_chunk)

    frame_idx = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frames.append(frame)
        frame_idx += 1

        if len(frames) == chunk_size or frame_idx == frame_count:
            results = process_chunk(frames)
            for bits in results:
                all_bits.extend(bits)
            frames = []
            pbar.update(len(results))

    pbar.close()
    pool.close()
    pool.join()
    cap.release()

    
    if len(all_bits) < 32:
        raise ValueError("Not enough bits for magic header")

    first_4_bytes = bits_to_bytes(all_bits[:32])
    has_magic = input_video.endswith(".vdb") and first_4_bytes == MAGIC_HEADER

    header_bytes_len = 4 if has_magic else 0

    
    if len(all_bits) < (header_bytes_len + 1) * 8:
        raise ValueError("Not enough bits for filename length in metadata")

    fn_len_bits = all_bits[header_bytes_len * 8 : header_bytes_len * 8 + 8]
    fn_len = bits_to_bytes(fn_len_bits)[0]

    if fn_len == 0 or fn_len > 255:
        raise ValueError("Invalid filename length in metadata")

    real_meta_len = 1 + fn_len + 8 + 8 + 32

    if len(all_bits) < (header_bytes_len + real_meta_len) * 8:
        raise ValueError("Not enough bits for full metadata")

    meta_bits = all_bits[header_bytes_len * 8 : header_bytes_len * 8 + real_meta_len * 8]
    meta_bytes = bits_to_bytes(meta_bits)

    filename, original_filesize, compressed_filesize, checksum = decode_metadata(meta_bytes)

    data_start_bit = (header_bytes_len + real_meta_len) * 8

    if len(all_bits) < data_start_bit + compressed_filesize * 8:
        raise ValueError("Not enough bits for compressed data")

    compressed_bits = all_bits[data_start_bit : data_start_bit + compressed_filesize * 8]
    compressed_bytes = bits_to_bytes(compressed_bits)

    data_checksum = calc_sha256(compressed_bytes)
    if data_checksum != checksum:
        print("Warning: SHA256 checksum mismatch on compressed data!")
    else:
        print("Checksum OK.")

    try:
        decompressed_data = zlib.decompress(compressed_bytes)
    except Exception as e:
        print(f"Decompression failed: {e}")
        return

    os.makedirs(output_folder, exist_ok=True)
    print(f"Decoded filename: {filename}")
    output_path = os.path.join(output_folder, filename)
    with open(output_path, 'wb') as f_out:
        f_out.write(decompressed_data)

    print(f"File saved to: {output_path}")



def download_video(url, output_path='downloaded_video.mp4'):
    if yt_dlp is None:
        raise ImportError("yt-dlp module not installed.")
    ydl_opts = {
        'format': 'mp4',
        'outtmpl': output_path,
        'quiet': True,
        'no_warnings': True,
    }
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        ydl.download([url])
    return output_path



def main():
    if len(sys.argv) == 2 and sys.argv[1].endswith(".vdb") and os.path.isfile(sys.argv[1]):
        print(f"Detected direct .vdb file: {sys.argv[1]}")
        decode_video_to_file(sys.argv[1], os.getcwd())
        return

    parser = argparse.ArgumentParser(description="Encode/decode files to/from YouTube-friendly color bit-grid video")
    subparsers = parser.add_subparsers(dest='command', required=True)

    encode_parser = subparsers.add_parser('encode', help='Encode file into video')
    encode_parser.add_argument('input_file', help='File to encode')
    encode_parser.add_argument('output_video', help='Output video file (.vdb or .mp4)')

    decode_parser = subparsers.add_parser('decode', help='Decode file from video')
    decode_parser.add_argument('input_video', help='Input video file')
    decode_parser.add_argument('output_folder', help='Folder to save decoded file')

    download_parser = subparsers.add_parser('download', help='Download YouTube video')
    download_parser.add_argument('url', help='YouTube URL to download')

    args = parser.parse_args()

    if args.command == 'encode':
        encode_file_to_video(args.input_file, args.output_video)
    elif args.command == 'decode':
        decode_video_to_file(args.input_video, args.output_folder)
    elif args.command == 'download':
        out = download_video(args.url)
        print(f"Downloaded video saved to: {out}")

if __name__ == '__main__':
    main()
