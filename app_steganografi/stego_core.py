import io
import math
import struct

import numpy as np
from PIL import Image, ImageFilter

MAGIC = b"LSB1"
HEADER_SIZE = len(MAGIC) + 4
DCT_BLOCK_SIZE = 8
DCT_STRENGTH = 48.0
DCT_MATRIX = np.array(
    [
        [
            math.sqrt(1 / DCT_BLOCK_SIZE)
            if frequency == 0
            else math.sqrt(2 / DCT_BLOCK_SIZE)
            * math.cos((2 * position + 1) * frequency * math.pi / (2 * DCT_BLOCK_SIZE))
            for frequency in range(DCT_BLOCK_SIZE)
        ]
        for position in range(DCT_BLOCK_SIZE)
    ],
    dtype=np.float32,
)


def _bytes_to_bits(data: bytes):
    for value in data:
        for shift in range(7, -1, -1):
            yield (value >> shift) & 1


def _bits_to_bytes(bits):
    output = bytearray()
    value = 0
    for index, bit in enumerate(bits, start=1):
        value = (value << 1) | bit
        if index % 8 == 0:
            output.append(value)
            value = 0
    return bytes(output)


def _dct_blocks(image: Image.Image):
    width, height = image.size
    for top in range(0, height - DCT_BLOCK_SIZE + 1, DCT_BLOCK_SIZE):
        for left in range(0, width - DCT_BLOCK_SIZE + 1, DCT_BLOCK_SIZE):
            yield left, top


def max_message_bytes(image: Image.Image, method: str = "LSB") -> int:
    rgb = image.convert("RGB")
    if method == "DCT":
        available_bits = (rgb.width // DCT_BLOCK_SIZE) * (rgb.height // DCT_BLOCK_SIZE)
        return max(0, (available_bits - HEADER_SIZE * 8) // 8)
    return max(0, (rgb.width * rgb.height * 3 - HEADER_SIZE * 8) // 8)


def _packet(message: str) -> bytes:
    payload = message.encode("utf-8")
    return MAGIC + struct.pack(">I", len(payload)) + payload


def _embed_dct(image: Image.Image, packet: bytes) -> Image.Image:
    ycbcr = image.convert("YCbCr")
    luminance, chroma_blue, chroma_red = ycbcr.split()
    pixels = np.asarray(luminance, dtype=np.float32).copy()
    bits = iter(_bytes_to_bits(packet))

    for left, top in _dct_blocks(image):
        try:
            bit = next(bits)
        except StopIteration:
            break
        block = pixels[top : top + DCT_BLOCK_SIZE, left : left + DCT_BLOCK_SIZE]
        coefficients = DCT_MATRIX @ block @ DCT_MATRIX.T
        first = coefficients[3, 2]
        second = coefficients[2, 3]
        middle = (first + second) / 2
        target_difference = DCT_STRENGTH if bit else -DCT_STRENGTH
        coefficients[3, 2] = middle + target_difference / 2
        coefficients[2, 3] = middle - target_difference / 2
        pixels[top : top + DCT_BLOCK_SIZE, left : left + DCT_BLOCK_SIZE] = (
            DCT_MATRIX.T @ coefficients @ DCT_MATRIX
        )

    luminance = Image.fromarray(np.clip(pixels, 0, 255).astype(np.uint8))
    return Image.merge("YCbCr", (luminance, chroma_blue, chroma_red)).convert("RGB")


def embed_message(image: Image.Image, message: str, method: str = "LSB") -> Image.Image:
    rgb = image.convert("RGB")
    packet = _packet(message)
    capacity = max_message_bytes(rgb, method)
    if len(packet) - HEADER_SIZE > capacity:
        raise ValueError(
            f"Pesan terlalu besar. Kapasitas gambar hanya {capacity:,} byte."
        )
    if method == "DCT":
        return _embed_dct(rgb, packet)
    if method != "LSB":
        raise ValueError("Metode steganografi tidak dikenal.")

    bits = iter(_bytes_to_bits(packet))
    pixels = list(rgb.getdata())
    encoded = []
    for red, green, blue in pixels:
        channels = [red, green, blue]
        for channel_index in range(3):
            try:
                bit = next(bits)
            except StopIteration:
                break
            channels[channel_index] = (channels[channel_index] & 0xFE) | bit
        encoded.append(tuple(channels))

    result = Image.new("RGB", rgb.size)
    result.putdata(encoded)
    return result


def _read_bits(image: Image.Image, method: str, bit_count: int):
    if method == "LSB":
        channels = (channel & 1 for pixel in image.convert("RGB").getdata() for channel in pixel)
        return [bit for _, bit in zip(range(bit_count), channels)]
    if method != "DCT":
        raise ValueError("Metode steganografi tidak dikenal.")

    y_channel = image.convert("YCbCr").getchannel(0)
    pixels = np.asarray(y_channel, dtype=np.float32)
    bits = []
    for left, top in _dct_blocks(image):
        if len(bits) >= bit_count:
            break
        block = pixels[top : top + DCT_BLOCK_SIZE, left : left + DCT_BLOCK_SIZE]
        coefficients = DCT_MATRIX @ block @ DCT_MATRIX.T
        bits.append(int(coefficients[3, 2] >= coefficients[2, 3]))
    return bits


def extract_message(image: Image.Image, method: str = "LSB") -> str:
    rgb = image.convert("RGB")
    header_bits = _read_bits(rgb, method, HEADER_SIZE * 8)
    if len(header_bits) < HEADER_SIZE * 8:
        raise ValueError("Gambar terlalu kecil untuk memuat header pesan.")
    header = _bits_to_bytes(header_bits)
    if header[: len(MAGIC)] != MAGIC:
        raise ValueError(f"Gambar tidak memiliki pesan {method} yang valid.")

    message_length = struct.unpack(">I", header[len(MAGIC) :])[0]
    available = (
        rgb.width // DCT_BLOCK_SIZE * (rgb.height // DCT_BLOCK_SIZE)
        if method == "DCT"
        else rgb.width * rgb.height * 3
    ) - HEADER_SIZE * 8
    if message_length * 8 > available:
        raise ValueError("Data pesan pada gambar rusak atau tidak lengkap.")

    all_bits = _read_bits(rgb, method, HEADER_SIZE * 8 + message_length * 8)
    payload = _bits_to_bytes(all_bits[HEADER_SIZE * 8 :])
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Pesan tidak menggunakan format UTF-8 yang valid.") from error


def calculate_ber(image: Image.Image, message: str, method: str) -> float:
    expected_bits = list(_bytes_to_bits(message.encode("utf-8")))
    if not expected_bits:
        raise ValueError("Pesan tidak boleh kosong saat menghitung BER.")
    encoded_bits = _read_bits(image, method, HEADER_SIZE * 8 + len(expected_bits))
    actual_bits = encoded_bits[HEADER_SIZE * 8 :]
    errors = sum(actual != expected for actual, expected in zip(actual_bits, expected_bits))
    errors += len(expected_bits) - len(actual_bits)
    return errors / len(expected_bits)


def apply_attack(
    image: Image.Image,
    quality: int = 50,
    attack_type: str = "JPEG",
    blur_radius: float = 2.0,
    noise_stddev: float = 10.0,
    noise_seed: int = 0,
) -> Image.Image:
    rgb = image.convert("RGB")
    if attack_type == "Gaussian blur":
        if not math.isfinite(blur_radius) or blur_radius < 0:
            raise ValueError("Radius Gaussian blur harus berupa angka non-negatif.")
        return rgb.filter(ImageFilter.GaussianBlur(radius=blur_radius))
    if attack_type == "Gaussian noise":
        if not math.isfinite(noise_stddev) or noise_stddev < 0:
            raise ValueError("Standar deviasi Gaussian noise harus berupa angka non-negatif.")
        pixels = np.asarray(rgb, dtype=np.float32)
        noise = np.random.default_rng(noise_seed).normal(0, noise_stddev, pixels.shape)
        return Image.fromarray(np.clip(np.rint(pixels + noise), 0, 255).astype(np.uint8))
    if attack_type != "JPEG":
        raise ValueError("Jenis serangan tidak dikenal.")
    if not 1 <= quality <= 100:
        raise ValueError("Kualitas JPEG harus antara 1 sampai 100%.")
    output = io.BytesIO()
    rgb.save(output, format="JPEG", quality=quality)
    output.seek(0)
    with Image.open(output) as compressed:
        return compressed.convert("RGB").copy()