# ⚡ AI-SPScan v3.0

> **[ V6.3 - LAB INTEL ]**
> *Advanced Statistical Analysis | Adaptive Learning | Production Ready*

**AI-SPScan** adalah scanner kerentanan SharePoint yang ringan namun cerdas. Berbeda dengan scanner tradisional, alat ini menggunakan **Statistical AI Engine** untuk menganalisis respon server dan mendeteksi anomali keamanan tanpa memerlukan dependensi model machine learning yang berat.



---

### 🛡️ Fitur Unggulan

* **🤖 Statistical AI Engine:** Menggunakan metode pembobotan statistik untuk menentukan *Threat Score* dan tingkat risiko (Critical, High, Medium, Low).
* **🧩 Adaptive Payload System:** Secara otomatis menyesuaikan payload berdasarkan versi SharePoint target (2016, 2019, SE).
* **🤺 Evasion & Bypass:** Terintegrasi dengan `WAFBypass` (headers rotation) dan `CircuitBreaker` untuk mencegah pemblokiran IP saat pemindaian intensif.
* **🚀 High Concurrency:** Mendukung `ThreadPoolExecutor` untuk pemindaian massal yang cepat dan efisien.
* **📊 Insightful Reporting:** Memberikan rekomendasi mitigasi berdasarkan temuan pola (seperti *deserialization* atau *auth bypass*).

---

### ⚙️ Instalasi

```bash
# Clone the repository
git clone [https://github.com/kingzhat/AI-SPScan.git](https://github.com/kingzhat/AI-SPScan.git)
cd AI-SPScan

# Setup Environment
python3 -m venv ai_scanner_env
source ai_scanner_env/bin/activate

# Install Dependencies
pip install -r requirements.txt
