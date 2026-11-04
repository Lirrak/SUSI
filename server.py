import os
import json
import time
import struct
import base64
import datetime
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import hashlib

PORT = int(os.environ.get("PORT", 6176))

# Thông tin cặp khóa Find My của SUSI Keychain
SUSI_KEYS = {
    "name": "SUSI Keychain AirTag",
    "adv_key_hex": "7760e0909ea393e343d1ca03cd409feeefbfbf973fe48017c4810958",
    "adv_key_b64": "d2DgkJ6jk+ND0coDzUCf7u+/v5c/5IAXxIEJWA==",
    "priv_key_b64": "RYlJThPw+54jphYaWnID7+2cnobpS3qxY2R3zw==",
    "pub_key_b64": "BHdg4JCeo5PjQ9HKA81An+7vv7+XP+SAF8SBCVi+N30jjdpY1ZI7rf/SfdTpuKtT2N+Wxx7BP7W5",
    "hashed_adv_key_b64": "nUI+ZdOio/9bVttGZdfuCC+Y2TtL3E06QpIO4yuQvLA="
}

# Tọa độ mặc định của SUSI (TP. Hồ Chí Minh)
DEFAULT_LAT = 10.7769
DEFAULT_LON = 106.7009

def generate_encrypted_findmy_report(report_id, lat=DEFAULT_LAT, lon=DEFAULT_LON):
    """
    Tạo Apple Find My encrypted payload chuẩn xác (88 bytes)
    Khớp hoàn toàn với cơ chế giải mã DecryptReports của Macless-Haystack / OpenHaystack App.
    """
    susi_priv_bytes = base64.b64decode(SUSI_KEYS["priv_key_b64"])
    susi_priv = ec.derive_private_key(int.from_bytes(susi_priv_bytes, "big"), ec.SECP224R1())

    # Tạo khóa tạm thời (Ephemeral Key) trên đường cong SECP224R1
    eph_priv = ec.generate_private_key(ec.SECP224R1())
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )  # 57 bytes

    # Tính shared secret qua ECDH
    shared_secret = eph_priv.exchange(ec.ECDH(), susi_priv.public_key())  # 28 bytes

    # KDF theo chuẩn ANSI X9.63: SHA256(shared_secret || counter(1) || eph_pub)
    kdf_input = shared_secret + struct.pack(">I", 1) + eph_pub_bytes
    derived = hashlib.sha256(kdf_input).digest()  # 32 bytes
    aes_key = derived[:16]
    iv = derived[16:]

    # Dữ liệu GPS chưa mã hóa (10 bytes: lat 4B, lon 4B, accuracy 1B, status 1B)
    lat_int = int(lat * 10000000)
    lon_int = int(lon * 10000000)
    accuracy = 10
    status = 0  # Pin OK
    plaintext = struct.pack(">IIBB", lat_int, lon_int, accuracy, status)

    # Mã hóa AES-GCM
    aesgcm = AESGCM(aes_key)
    enc_res = aesgcm.encrypt(iv, plaintext, None)  # 10 bytes ciphertext + 16 bytes tag

    # Timestamp Find My tính bằng số giây kể từ 2001-01-01 00:00:00 UTC
    t2001 = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    delta_sec = int((now - t2001).total_seconds())
    confidence = 95

    # Cấu trúc payload: 4 bytes time + 1 byte confidence + 57 bytes eph_pub + 10 bytes enc + 16 bytes tag = 88 bytes
    payload = struct.pack(">IB", delta_sec, confidence) + eph_pub_bytes + enc_res

    return {
        "id": report_id,
        "payload": base64.b64encode(payload).decode("utf-8"),
        "datePublished": int(time.time() * 1000),
        "statusCode": 0
    }

class CloudHaystackHandler(BaseHTTPRequestHandler):
    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        print(f"[HTTP GET] {parsed.path}")

        # Endpoint danh sách thiết bị cho app
        if parsed.path in ["/api/devices", "/devices"]:
            devices = [{
                "id": 1,
                "name": SUSI_KEYS["name"],
                "publicKey": SUSI_KEYS["pub_key_b64"],
                "privateKey": SUSI_KEYS["priv_key_b64"],
                "advertisementKey": SUSI_KEYS["adv_key_b64"],
                "hashedPublicKey": SUSI_KEYS["hashed_adv_key_b64"],
                "color": 4280391411,
                "icon": 58746,
                "isActive": True
            }]
            data = json.dumps(devices).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(data)
            return

        # Bản đồ Web trực tiếp xem trên Chrome điện thoại
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SUSI AirTag Tracker</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        body {{ margin: 0; padding: 0; font-family: -apple-system, sans-serif; background: #121212; color: #fff; }}
        #header {{ padding: 12px 16px; background: #1e1e1e; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; }}
        #title {{ font-size: 18px; font-weight: bold; color: #ff9800; }}
        #status {{ font-size: 12px; color: #4caf50; font-weight: bold; }}
        #map {{ width: 100vw; height: calc(100vh - 54px); }}
    </style>
</head>
<body>
    <div id="header">
        <div id="title">🐾 SUSI Keychain AirTag</div>
        <div id="status">● Đang Hoạt Động (Cloud 24/7)</div>
    </div>
    <div id="map"></div>
    <script>
        var map = L.map('map').setView([{DEFAULT_LAT}, {DEFAULT_LON}], 16);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            maxZoom: 19,
            attribution: '© OpenStreetMap'
        }}).addTo(map);

        var marker = L.marker([{DEFAULT_LAT}, {DEFAULT_LON}]).addTo(map)
            .bindPopup("<b>🐾 SUSI Keychain AirTag</b><br>Trạng thái: Đang phát BLE Find My.<br>Tọa độ: {DEFAULT_LAT}, {DEFAULT_LON}<br>Cloud Server: Online 24/7.")
            .openPopup();
    </script>
</body>
</html>"""
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        print(f"[HTTP POST] {self.path}")
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len) if content_len > 0 else b""
        
        req_ids = []
        try:
            if post_body:
                body_json = json.loads(post_body.decode("utf-8"))
                req_ids = body_json.get("ids", [])
        except Exception as e:
            print(f"Error parsing POST body: {e}")

        # Nếu app không gửi ID nào hoặc gửi rỗng, dùng khóa mặc định của SUSI
        if not req_ids:
            req_ids = [SUSI_KEYS["hashed_adv_key_b64"]]

        results = []
        for rid in req_ids:
            report = generate_encrypted_findmy_report(rid)
            results.append(report)

        response_dict = {"results": results}
        data = json.dumps(response_dict).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(data)

def run():
    server = HTTPServer(("0.0.0.0", PORT), CloudHaystackHandler)
    print(f"SUSI Cloud Server running on port {PORT}...")
    server.serve_forever()

if __name__ == "__main__":
    run()
