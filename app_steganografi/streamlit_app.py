import io

import numpy as np
import pandas as pd
import streamlit as st
from PIL import Image
from skimage.metrics import structural_similarity

from app import (
	apply_attack,
	calculate_ber,
	embed_message,
	extract_message,
	max_message_bytes,
)


st.set_page_config(page_title="Steganografi", page_icon="🔐", layout="wide")

if "stego_png" not in st.session_state:
	st.session_state.stego_png = None
if "stego_upload_version" not in st.session_state:
	st.session_state.stego_upload_version = 0
if "uploaded_stego_png" not in st.session_state:
	st.session_state.uploaded_stego_png = None
if "secret_message" not in st.session_state:
	st.session_state.secret_message = ""
if "encoded_method" not in st.session_state:
	st.session_state.encoded_method = None
if "attack_results" not in st.session_state:
	st.session_state.attack_results = {}
if "attack_messages" not in st.session_state:
	st.session_state.attack_messages = {}
if "extracted_message" not in st.session_state:
	st.session_state.extracted_message = None
if "extraction_error" not in st.session_state:
	st.session_state.extraction_error = None
if "metric_results" not in st.session_state:
	st.session_state.metric_results = None


def image_from_bytes(data: bytes) -> Image.Image:
	with Image.open(io.BytesIO(data)) as image:
		return image.convert("RGB").copy()


def active_stego_bytes() -> bytes | None:
	return st.session_state.uploaded_stego_png


def calculate_metrics(original: Image.Image, compared: Image.Image):
	if original.size != compared.size:
		compared = compared.resize(original.size, Image.Resampling.LANCZOS)
	original_array = np.asarray(original, dtype=np.uint8)
	compared_array = np.asarray(compared, dtype=np.uint8)
	difference = original_array.astype(np.float64) - compared_array.astype(np.float64)
	mse = float(np.mean(difference**2))
	psnr = float("inf") if mse == 0 else float(10 * np.log10((255.0**2) / mse))
	ssim = float(
		structural_similarity(
			original_array,
			compared_array,
			channel_axis=2,
			data_range=255,
		)
	)
	return mse, psnr, ssim


st.title("Steganografi gambar")
st.caption("Sisipkan dan ekstrak pesan, lalu uji ketahanan LSB atau DCT.")

cover_file = st.file_uploader(
	"Gambar cover",
	type=("png", "jpg", "jpeg", "bmp", "tif", "tiff"),
	key="cover_upload",
)
method = st.selectbox("Metode steganografi", ("LSB", "DCT"), key="stego_method")

if cover_file is not None:
	cover_bytes = cover_file.getvalue()
	cover_image = image_from_bytes(cover_bytes)
	col_image, col_info = st.columns((2, 1))
	with col_image:
		st.image(cover_image, caption="Cover", use_container_width=True)
	with col_info:
		st.metric("Kapasitas payload", f"{max_message_bytes(cover_image, method):,} byte")
else:
	cover_bytes = None
	cover_image = None

encode_tab, extract_tab, attack_tab, metrics_tab = st.tabs(
	("Sisipkan", "Ekstrak", "Serangan dan BER", "Metrik citra")
)

with encode_tab:
	st.subheader("Sisipkan pesan")
	message = st.text_area("Pesan rahasia", height=180, key="message_to_encode")
	payload_size = len(message.encode("utf-8"))
	st.caption(f"Ukuran payload UTF-8: {payload_size:,} byte")

	if st.button("Sisipkan pesan", type="primary", disabled=cover_image is None):
		if not message:
			st.error("Masukkan pesan terlebih dahulu.")
		else:
			try:
				encoded = embed_message(cover_image, message, method)
				output = io.BytesIO()
				encoded.save(output, format="PNG")
				st.session_state.stego_png = output.getvalue()
				st.session_state.secret_message = message
				st.session_state.encoded_method = method
				st.session_state.stego_upload_version += 1
				st.session_state.uploaded_stego_png = None
				st.session_state.attack_results = {}
				st.session_state.attack_messages = {}
				st.session_state.extracted_message = None
				st.session_state.extraction_error = None
				st.session_state.metric_results = None
				st.success("Pesan berhasil disisipkan.")
			except Exception as error:
				st.error(str(error))

	if st.session_state.stego_png is not None:
		st.image(st.session_state.stego_png, caption="Hasil stego", use_container_width=True)
		st.download_button(
			"Unduh gambar stego (PNG)",
			data=st.session_state.stego_png,
			file_name="gambar_stego.png",
			mime="image/png",
		)
		st.info("Setelah mengunduh gambar, buka tab Ekstrak dan unggah kembali file stego tersebut.")

with extract_tab:
	st.subheader("Ekstrak pesan")
	if st.session_state.stego_png is None:
		st.info("Unggah gambar cover dan sisipkan pesan terlebih dahulu.")
	else:
		uploaded_stego_file = st.file_uploader(
			"Unggah gambar stego yang sudah diunduh",
			type=("png", "jpg", "jpeg", "bmp", "tif", "tiff"),
			key=f"stego_upload_{st.session_state.stego_upload_version}",
		)
		if uploaded_stego_file is not None:
			st.session_state.uploaded_stego_png = uploaded_stego_file.getvalue()
		current_stego = active_stego_bytes()
		if current_stego is None:
			st.info("Pilih file gambar stego hasil unduhan untuk melanjutkan.")
		else:
			if st.session_state.encoded_method and st.session_state.encoded_method != method:
				st.warning(f"Gambar yang dibuat memakai {st.session_state.encoded_method}; pilih metode yang sama untuk ekstraksi.")
			if st.button("Ekstrak pesan", key="extract_message_button"):
				try:
					st.session_state.extracted_message = extract_message(image_from_bytes(current_stego), method)
					st.session_state.extraction_error = None
				except Exception as error:
					st.session_state.extracted_message = None
					st.session_state.extraction_error = str(error)
			if st.session_state.extraction_error:
				st.error(st.session_state.extraction_error)
			elif st.session_state.extracted_message is not None:
				st.text_area(
					"Pesan hasil ekstraksi",
					value=st.session_state.extracted_message,
					height=180,
					disabled=True,
				)

with attack_tab:
	st.subheader("Bandingkan serangan")
	current_stego = active_stego_bytes()
	attack_message = st.text_area(
		"Pesan asli untuk menghitung BER",
		value=st.session_state.secret_message,
		key="attack_message",
	)
	jpeg_quality = st.slider("Kualitas JPEG (%)", 1, 100, 50)
	blur_radius = st.slider("Radius Gaussian blur", 0.0, 10.0, 2.0, 0.1)
	noise_stddev = st.slider("Sigma Gaussian noise", 0.0, 50.0, 10.0, 0.5)

	if st.button(
		"Jalankan semua serangan",
		type="primary",
		disabled=current_stego is None or not attack_message,
	):
		try:
			source_image = image_from_bytes(current_stego)
			attacks = (
				("JPEG", {"quality": jpeg_quality}),
				("Gaussian blur", {"attack_type": "Gaussian blur", "blur_radius": blur_radius}),
				(
					"Gaussian noise",
					{"attack_type": "Gaussian noise", "noise_stddev": noise_stddev},
				),
			)
			results = {}
			extracted_messages = {}
			for attack_name, parameters in attacks:
				attacked = apply_attack(source_image, **parameters)
				results[attack_name] = calculate_ber(attacked, attack_message, method)
				try:
					extracted_messages[attack_name] = extract_message(attacked, method)
				except ValueError as error:
					extracted_messages[attack_name] = f"Ekstraksi gagal: {error}"
			st.session_state.attack_results = results
			st.session_state.attack_messages = extracted_messages
		except Exception as error:
			st.error(str(error))

	if st.session_state.attack_results:
		chart_data = pd.DataFrame(
			{"BER (%)": [ber * 100 for ber in st.session_state.attack_results.values()]},
			index=list(st.session_state.attack_results),
		)
		st.bar_chart(chart_data)
		for attack_name, ber in st.session_state.attack_results.items():
			st.write(f"**{attack_name}:** {ber:.4%} BER")
			st.text_area(
				f"Pesan hasil ekstraksi: {attack_name}",
				value=st.session_state.attack_messages[attack_name],
				height=110,
				disabled=True,
				key=f"extracted_{attack_name}",
			)
	elif current_stego is None:
		st.info("Buat gambar stego, unduh, lalu unggah kembali pada tab Ekstrak.")

with metrics_tab:
	st.subheader("MSE, PSNR, dan SSIM")
	current_stego = active_stego_bytes()
	if cover_image is None or current_stego is None:
		st.info("Pilih gambar cover, lalu unggah gambar stego hasil unduhan pada tab Ekstrak.")
	elif st.button("Hitung metrik", key="calculate_metrics_button"):
		try:
			st.session_state.metric_results = calculate_metrics(cover_image, image_from_bytes(current_stego))
		except Exception as error:
			st.session_state.metric_results = None
			st.error(str(error))
	if st.session_state.metric_results is not None:
		mse, psnr, ssim = st.session_state.metric_results
		metric_columns = st.columns(3)
		metric_columns[0].metric("MSE", f"{mse:.6f}")
		metric_columns[1].metric("PSNR", "∞ dB" if np.isinf(psnr) else f"{psnr:.4f} dB")
		metric_columns[2].metric("SSIM", f"{ssim:.6f}")
