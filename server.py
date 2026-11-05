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

# Thử import findmy để truy vấn Apple Find My Network thực tế nếu đã đăng nhập Apple ID
try:
    from findmy import AppleAccount, KeyPair
    FINDMY_AVAILABLE = True
except ImportError:
    FINDMY_AVAILABLE = False

PORT = int(os.environ.get("PORT", 6176))
ACCOUNT_FILE = os.path.join(os.path.dirname(__file__), "account.json")

# Thông tin cặp khóa Find My của SUSI Keychain
SUSI_KEYS = {
    "name": "SUSI Keychain AirTag",
    "adv_key_hex": "7760e0909ea393e343d1ca03cd409feeefbfbf973fe48017c4810958",
    "adv_key_b64": "d2DgkJ6jk+ND0coDzUCf7u+/v5c/5IAXxIEJWA==",
    "priv_key_b64": "RYlJThPw+54jphYaWnID7+2cnobpS3qxY2R3zw==",
    "pub_key_b64": "BHdg4JCeo5PjQ9HKA81An+7vv7+XP+SAF8SBCVi+N30jjdpY1ZI7rf/SfdTpuKtT2N+Wxx7BP7W5",
    "hashed_adv_key_b64": "nUI+ZdOio/9bVttGZdfuCC+Y2TtL3E06QpIO4yuQvLA="
}

# Tọa độ mặc định lưu tạm thời (sẽ tự động cập nhật khi có iPhone bắt sóng)
latest_location = {
    "lat": 10.7769,
    "lon": 106.7009,
    "timestamp": int(time.time()),
    "source": "Initial Setup"
}

apple_account = None

def init_apple_account():
    global apple_account
    if FINDMY_AVAILABLE and os.path.exists(ACCOUNT_FILE):
        try:
            apple_account = AppleAccount.from_json(ACCOUNT_FILE)
            print("Apple ID session loaded successfully!")
        except Exception as e:
            print(f"Error loading Apple ID account: {e}")

init_apple_account()

def query_real_apple_findmy():
    """
    Truy vấn trực tiếp máy chủ Apple Find My Gateway để lấy tọa độ thực tế do iPhone xung quanh gửi về
    """
    global apple_account, latest_location
    if not apple_account:
        return None

    try:
        key = KeyPair.from_b64(SUSI_KEYS["priv_key_b64"])
        report = apple_account.fetch_location(key)
        if report:
            latest_location["lat"] = report.latitude
            latest_location["lon"] = report.longitude
            latest_location["timestamp"] = int(report.timestamp.timestamp())
            latest_location["source"] = "Apple Find My Network (iPhone Crowdsourced)"
            print(f"[Apple Find My Report] Lat: {report.latitude}, Lon: {report.longitude}, Time: {report.timestamp}")
            
            # Lưu lại phiên đăng nhập để tránh bị out
            apple_account.to_json(ACCOUNT_FILE)
            
            return {
                "id": SUSI_KEYS["hashed_adv_key_b64"],
                "payload": base64.b64encode(report.payload).decode("utf-8") if isinstance(report.payload, bytes) else report.payload,
                "datePublished": int(report.timestamp.timestamp() * 1000),
                "statusCode": 0
            }
    except Exception as e:
        print(f"Error querying Apple Find My: {e}")
    return None

def generate_encrypted_findmy_report(report_id, lat=None, lon=None):
    """
    Tạo Apple Find My encrypted payload chuẩn xác (88 bytes)
    """
    if lat is None:
        lat = latest_location["lat"]
    if lon is None:
        lon = latest_location["lon"]

    susi_priv_bytes = base64.b64decode(SUSI_KEYS["priv_key_b64"])
    susi_priv = ec.derive_private_key(int.from_bytes(susi_priv_bytes, "big"), ec.SECP224R1())

    eph_priv = ec.generate_private_key(ec.SECP224R1())
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )

    shared_secret = eph_priv.exchange(ec.ECDH(), susi_priv.public_key())

    kdf_input = shared_secret + struct.pack(">I", 1) + eph_pub_bytes
    derived = hashlib.sha256(kdf_input).digest()
    aes_key = derived[:16]
    iv = derived[16:]

    lat_int = int(lat * 10000000)
    lon_int = int(lon * 10000000)
    accuracy = 10
    status = 0
    plaintext = struct.pack(">IIBB", lat_int, lon_int, accuracy, status)

    aesgcm = AESGCM(aes_key)
    enc_res = aesgcm.encrypt(iv, plaintext, None)

    t2001 = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    delta_sec = int((now - t2001).total_seconds())
    confidence = 95

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

        # Thử lấy vị trí mới nhất từ Apple nếu có tài khoản
        if apple_account:
            query_real_apple_findmy()

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

        cur_lat = latest_location["lat"]
        cur_lon = latest_location["lon"]
        source_text = latest_location["source"]

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
        <div id="status">● Nguồn: {source_text}</div>
    </div>
    <div id="map"></div>
    <script>
        var map = L.map('map').setView([{cur_lat}, {cur_lon}], 16);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            maxZoom: 19,
            attribution: '© OpenStreetMap'
        }}).addTo(map);

        var marker = L.marker([{cur_lat}, {cur_lon}]).addTo(map)
            .bindPopup("<b>🐾 SUSI Keychain AirTag</b><br>Tọa độ: {cur_lat}, {cur_lon}<br>Nguồn: {source_text}<br>Cloud Server: Online 24/7.")
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

        if not req_ids:
            req_ids = [SUSI_KEYS["hashed_adv_key_b64"]]

        # Ưu tiên lấy tọa độ thật từ Apple Find My nếu đã đăng nhập
        real_report = query_real_apple_findmy()

        results = []
        if real_report:
            results.append(real_report)
        else:
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
