import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image

from stego_core import (
	apply_attack,
	calculate_ber,
	embed_message,
	extract_message,
	max_message_bytes,
)


class SteganographyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Steganografi | LSB dan DCT")
        self.geometry("900x700")
        self.minsize(620, 440)
        self.image_path = tk.StringVar()
        self.method = tk.StringVar(value="LSB")
        self.jpeg_quality = tk.IntVar(value=50)
        self.blur_radius = tk.DoubleVar(value=2.0)
        self.noise_stddev = tk.DoubleVar(value=10.0)
        self.capacity_text = tk.StringVar(value="Kapasitas: -")
        self.payload_size_text = tk.StringVar(value="Ukuran payload UTF-8: 0 byte")
        self.ber_text = tk.StringVar(value="BER: -")
        self.attack_ber_results = {}
        self._build_ui()

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        viewport = ttk.Frame(self)
        viewport.pack(fill="both", expand=True)
        canvas = tk.Canvas(viewport, highlightthickness=0)
        scrollbar = ttk.Scrollbar(viewport, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        root = ttk.Frame(canvas, padding=16)
        content_window = canvas.create_window((0, 0), window=root, anchor="nw")
        root.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(content_window, width=event.width))
        canvas.bind_all("<MouseWheel>", lambda event: canvas.yview_scroll(-1 * (event.delta // 120), "units"))
        ttk.Label(root, text="STEGANOGRAFI", font=("Segoe UI", 19, "bold")).pack(anchor="w")
        ttk.Label(root, text="Sisipkan, ekstrak, dan uji ketahanan pesan.").pack(anchor="w", pady=(2, 12))

        image_frame = ttk.LabelFrame(root, text="Gambar", padding=12)
        image_frame.pack(fill="x", pady=(0, 10))
        image_row = ttk.Frame(image_frame)
        image_row.pack(fill="x")
        ttk.Entry(image_row, textvariable=self.image_path).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(image_row, text="Pilih gambar", command=self.choose_image).pack(side="left")
        ttk.Label(image_row, text="Metode").pack(side="left", padx=(12, 5))
        method_select = ttk.Combobox(image_row, textvariable=self.method, values=("LSB", "DCT"), state="readonly", width=8)
        method_select.pack(side="left")
        method_select.bind("<<ComboboxSelected>>", self.update_capacity)
        ttk.Label(image_frame, textvariable=self.capacity_text).pack(anchor="w", pady=(8, 0))

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        encode_tab = ttk.Frame(notebook, padding=16)
        decode_tab = ttk.Frame(notebook, padding=16)
        attack_tab = ttk.Frame(notebook, padding=16)
        notebook.add(encode_tab, text="Sisipkan pesan")
        notebook.add(decode_tab, text="Ekstrak pesan")
        notebook.add(attack_tab, text="Uji serangan dan BER")

        ttk.Label(encode_tab, text="Pesan rahasia").pack(anchor="w")
        self.message_box = tk.Text(encode_tab, height=12, wrap="word", font=("Segoe UI", 11), undo=True)
        self.message_box.pack(fill="both", expand=True, pady=(7, 12))
        self.message_box.bind("<KeyRelease>", self.update_payload_size)
        ttk.Label(encode_tab, textvariable=self.payload_size_text).pack(anchor="w", pady=(0, 8))
        ttk.Button(encode_tab, text="Sisipkan dan simpan PNG", command=self.encode).pack(anchor="e")

        ttk.Label(decode_tab, text="Pesan hasil ekstraksi").pack(anchor="w")
        self.extracted_box = tk.Text(decode_tab, height=12, wrap="word", font=("Segoe UI", 11), state="disabled")
        self.extracted_box.pack(fill="both", expand=True, pady=(7, 12))
        ttk.Button(decode_tab, text="Ekstrak pesan", command=self.decode).pack(anchor="e")

        ttk.Label(attack_tab, text="Bandingkan BER dari tiga serangan pada gambar stego yang dipilih.").pack(anchor="w")
        attack_settings = ttk.LabelFrame(attack_tab, text="Parameter serangan", padding=10)
        attack_settings.pack(fill="x", pady=(12, 0))
        ttk.Label(attack_settings, text="Kualitas JPEG (%)").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=3)
        ttk.Spinbox(
            attack_settings,
            from_=1,
            to=100,
            increment=1,
            textvariable=self.jpeg_quality,
            width=8,
        ).grid(row=0, column=1, sticky="w", pady=3)
        ttk.Label(attack_settings, text="Radius Gaussian blur").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=3)
        ttk.Spinbox(
            attack_settings,
            from_=0,
            to=20,
            increment=0.5,
            textvariable=self.blur_radius,
            width=8,
        ).grid(row=1, column=1, sticky="w", pady=3)
        ttk.Label(attack_settings, text="Sigma Gaussian noise").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=3)
        ttk.Spinbox(
            attack_settings,
            from_=0,
            to=100,
            increment=1,
            textvariable=self.noise_stddev,
            width=8,
        ).grid(row=2, column=1, sticky="w", pady=3)
        ttk.Button(attack_tab, text="Bandingkan semua serangan", command=self.test_attack).pack(anchor="w", pady=(12, 8))
        ttk.Label(attack_tab, textvariable=self.ber_text, font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.ber_chart = tk.Canvas(attack_tab, height=250, background="white", highlightthickness=1, highlightbackground="#cccccc")
        self.ber_chart.pack(fill="x", expand=True, pady=(8, 12))
        self.ber_chart.bind("<Configure>", self.draw_ber_chart)
        ttk.Label(attack_tab, text="Pesan hasil ekstraksi setelah serangan").pack(anchor="w", pady=(14, 4))
        self.attack_extracted_box = tk.Text(attack_tab, height=7, wrap="word", font=("Segoe UI", 10), state="disabled")
        self.attack_extracted_box.pack(fill="both", expand=True)
        ttk.Label(
            attack_tab,
            text="BER = jumlah bit pesan yang salah atau hilang dibagi jumlah bit pesan.",
            foreground="#555555",
        ).pack(anchor="w", pady=(8, 0))

    def choose_image(self):
        path = filedialog.askopenfilename(
            title="Pilih gambar",
            filetypes=[("Gambar", "*.png *.jpg *.jpeg *.bmp *.tif *.tiff"), ("Semua file", "*.*")],
        )
        if not path:
            return
        self.image_path.set(path)
        self.update_capacity()

    def update_capacity(self, _event=None):
        if not self.image_path.get():
            self.capacity_text.set("Kapasitas: -")
            return
        try:
            with Image.open(self.image_path.get()) as image:
                method = self.method.get()
                self.capacity_text.set(f"Kapasitas {method}: {max_message_bytes(image, method):,} byte")
        except Exception as error:
            self.capacity_text.set("Kapasitas: -")
            messagebox.showerror("Gagal membuka gambar", str(error))

    def update_payload_size(self, _event=None):
        message = self.message_box.get("1.0", "end-1c")
        payload_size = len(message.encode("utf-8"))
        self.payload_size_text.set(f"Ukuran payload UTF-8: {payload_size:,} byte")

    def draw_ber_chart(self, _event=None):
        chart = self.ber_chart
        chart.delete("all")
        width = max(chart.winfo_width(), 420)
        height = max(chart.winfo_height(), 250)
        left, right, top, bottom = 58, 18, 26, 44
        plot_height = height - top - bottom
        plot_width = width - left - right

        for percentage in range(0, 101, 25):
            y = top + plot_height * (1 - percentage / 100)
            chart.create_line(left, y, width - right, y, fill="#d9dee5")
            chart.create_text(left - 8, y, text=f"{percentage}%", anchor="e", fill="#333333")

        attacks = ("JPEG", "Gaussian blur", "Gaussian noise")
        bar_width = min(72, plot_width / (len(attacks) * 2))
        colors = ("#258c8c", "#e09f3e", "#5875a4")
        for index, (attack, color) in enumerate(zip(attacks, colors)):
            center_x = left + plot_width * (index + 0.5) / len(attacks)
            ber = self.attack_ber_results.get(attack)
            if ber is not None:
                bar_height = plot_height * ber
                chart.create_rectangle(
                    center_x - bar_width / 2,
                    top + plot_height - bar_height,
                    center_x + bar_width / 2,
                    top + plot_height,
                    fill=color,
                    outline="",
                )
                chart.create_text(center_x, max(top + 8, top + plot_height - bar_height - 12), text=f"{ber * 100:.2f}%")
            chart.create_text(center_x, height - bottom + 22, text=attack, fill="#222222")

        if not self.attack_ber_results:
            chart.create_text(left + plot_width / 2, top + plot_height / 2, text="Jalankan pengujian untuk melihat grafik BER", fill="#555555")

    def encode(self):
        if not self.image_path.get():
            messagebox.showwarning("Gambar belum dipilih", "Pilih gambar terlebih dahulu.")
            return
        message = self.message_box.get("1.0", "end-1c")
        if not message:
            messagebox.showwarning("Pesan kosong", "Masukkan pesan yang ingin disisipkan.")
            return
        output_path = filedialog.asksaveasfilename(
            title="Simpan gambar stego",
            defaultextension=".png",
            filetypes=[("PNG", "*.png")],
            initialfile=f"{Path(self.image_path.get()).stem}_stego.png",
        )
        if not output_path:
            return
        try:
            with Image.open(self.image_path.get()) as image:
                encoded = embed_message(image, message, self.method.get())
                encoded.save(output_path, "PNG")
            self.image_path.set(output_path)
            self.update_capacity()
            messagebox.showinfo("Berhasil", f"Pesan berhasil disisipkan ke:\n{output_path}")
        except Exception as error:
            messagebox.showerror("Gagal menyisipkan pesan", str(error))

    def decode(self):
        if not self.image_path.get():
            messagebox.showwarning("Gambar belum dipilih", "Pilih gambar terlebih dahulu.")
            return
        try:
            with Image.open(self.image_path.get()) as image:
                message = extract_message(image, self.method.get())
            self.extracted_box.configure(state="normal")
            self.extracted_box.delete("1.0", "end")
            self.extracted_box.insert("1.0", message)
            self.extracted_box.configure(state="disabled")
        except Exception as error:
            messagebox.showerror("Gagal mengekstrak pesan", str(error))

    def test_attack(self):
        if not self.image_path.get():
            messagebox.showwarning("Gambar belum dipilih", "Pilih gambar stego terlebih dahulu.")
            return
        message = self.message_box.get("1.0", "end-1c")
        if not message:
            messagebox.showwarning("Pesan kosong", "Masukkan pesan asli pada tab sisipkan terlebih dahulu.")
            return
        try:
            with Image.open(self.image_path.get()) as image:
                stego = image.convert("RGB").copy()
            attacks = (
                ("JPEG", {"quality": self.jpeg_quality.get()}),
                ("Gaussian blur", {"attack_type": "Gaussian blur", "blur_radius": self.blur_radius.get()}),
                (
                    "Gaussian noise",
                    {"attack_type": "Gaussian noise", "noise_stddev": self.noise_stddev.get()},
                ),
            )
            results = {}
            extracted_messages = []
            for attack_name, parameters in attacks:
                attacked = apply_attack(stego, **parameters)
                results[attack_name] = calculate_ber(attacked, message, self.method.get())
                try:
                    extracted = extract_message(attacked, self.method.get())
                except ValueError as error:
                    extracted = f"Ekstraksi gagal: {error}"
                extracted_messages.append(f"[{attack_name}]\n{extracted}")

            self.attack_ber_results = results
            self.draw_ber_chart()
            summary = " | ".join(f"{name}: {ber * 100:.2f}%" for name, ber in results.items())
            self.ber_text.set(f"BER: {summary}")
            self.attack_extracted_box.configure(state="normal")
            self.attack_extracted_box.delete("1.0", "end")
            self.attack_extracted_box.insert("1.0", "\n\n".join(extracted_messages))
            self.attack_extracted_box.configure(state="disabled")
        except Exception as error:
            messagebox.showerror("Gagal menguji serangan", str(error))


if __name__ == "__main__":
    SteganographyApp().mainloop()
