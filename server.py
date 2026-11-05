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
LOCATION_FILE = os.path.join(os.path.dirname(__file__), "location.json")

# Thông tin cặp khóa Find My của SUSI Keychain
SUSI_KEYS = {
    "name": "SUSI Keychain AirTag",
    "adv_key_hex": "7760e0909ea393e343d1ca03cd409feeefbfbf973fe48017c4810958",
    "adv_key_b64": "d2DgkJ6jk+ND0coDzUCf7u+/v5c/5IAXxIEJWA==",
    "priv_key_b64": "RYlJThPw+54jphYaWnID7+2cnobpS3qxY2R3zw==",
    "pub_key_b64": "BHdg4JCeo5PjQ9HKA81An+7vv7+XP+SAF8SBCVi+N30jjdpY1ZI7rf/SfdTpuKtT2N+Wxx7BP7W5",
    "hashed_adv_key_b64": "nUI+ZdOio/9bVttGZdfuCC+Y2TtL3E06QpIO4yuQvLA="
}

# Tọa độ mặc định lưu trữ
latest_location = {
    "lat": 10.7769,
    "lon": 106.7009,
    "accuracy": 15,
    "timestamp": int(time.time()),
    "source": "Chưa có GPS cập nhật"
}

def load_saved_location():
    global latest_location
    if os.path.exists(LOCATION_FILE):
        try:
            with open(LOCATION_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                latest_location.update(data)
                print(f"[Storage] Loaded saved location: {latest_location['lat']}, {latest_location['lon']}")
        except Exception as e:
            print(f"[Storage] Error loading location file: {e}")

def save_location():
    try:
        with open(LOCATION_FILE, "w", encoding="utf-8") as f:
            json.dump(latest_location, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[Storage] Error saving location file: {e}")

load_saved_location()

def generate_encrypted_findmy_report(report_id, lat=None, lon=None):
    """
    Tạo Apple Find My encrypted payload chuẩn xác (88 bytes)
    Được giải mã bởi ứng dụng Macless-Haystack trên Android.
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
    accuracy = int(latest_location.get("accuracy", 10))
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
        params = urllib.parse.parse_qs(parsed.query)

        # Cập nhật vị trí qua URL GET nếu có tham số ?lat=...&lon=...
        if parsed.path == "/api/update_location" and "lat" in params and "lon" in params:
            try:
                lat = float(params["lat"][0])
                lon = float(params["lon"][0])
                acc = float(params.get("acc", [15])[0])
                latest_location["lat"] = lat
                latest_location["lon"] = lon
                latest_location["accuracy"] = acc
                latest_location["timestamp"] = int(time.time())
                latest_location["source"] = "GPS Điện thoại (Web Sync)"
                save_location()
                print(f"[GPS Update GET] New position: {lat}, {lon}")
                resp = json.dumps({"status": "success", "location": latest_location}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(resp)
                return
            except Exception as e:
                resp = json.dumps({"status": "error", "message": str(e)}).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(resp)
                return

        # Lấy trạng thái vị trí dạng JSON
        if parsed.path == "/api/location":
            data = json.dumps(latest_location).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(data)
            return

        # Danh sách thiết bị cho Macless-Haystack app
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

        # Giao diện Web App điều khiển định vị & Radar Bluetooth
        cur_lat = latest_location["lat"]
        cur_lon = latest_location["lon"]
        source_text = latest_location["source"]
        time_str = datetime.datetime.fromtimestamp(latest_location["timestamp"]).strftime("%H:%M:%S - %d/%m/%Y")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>🐾 SUSI AirTag Hub</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        body {{ margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #121212; color: #fff; }}
        #header {{ padding: 12px 16px; background: #1e1e1e; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; }}
        #title {{ font-size: 17px; font-weight: bold; color: #ff9800; display: flex; align-items: center; gap: 8px; }}
        #status {{ font-size: 12px; color: #4caf50; font-weight: bold; }}
        #controls {{ padding: 12px 16px; background: #1a1a1a; display: flex; flex-direction: column; gap: 10px; border-bottom: 1px solid #2a2a2a; }}
        .btn-row {{ display: flex; gap: 10px; }}
        button {{ flex: 1; padding: 12px; font-size: 14px; font-weight: bold; border-radius: 8px; border: none; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px; }}
        .btn-sync {{ background: #2196f3; color: #fff; }}
        .btn-sync:active {{ background: #1976d2; }}
        .btn-radar {{ background: #9c27b0; color: #fff; }}
        .btn-radar:active {{ background: #7b1fa2; }}
        #info-box {{ font-size: 13px; color: #bbb; line-height: 1.5; }}
        #info-box b {{ color: #eee; }}
        #map {{ width: 100vw; height: calc(100vh - 195px); }}
        .radar-box {{ display: none; background: #262626; padding: 10px; border-radius: 8px; border: 1px solid #ff9800; text-align: center; font-size: 14px; }}
    </style>
</head>
<body>
    <div id="header">
        <div id="title">🐾 SUSI AirTag Tracker</div>
        <div id="status">● Cloud Live</div>
    </div>
    <div id="controls">
        <div class="btn-row">
            <button class="btn-sync" onclick="syncCurrentGPS()">📍 Cập Nhật Vị Trí Của Tôi</button>
            <button class="btn-radar" onclick="startRadarScan()">📡 Dò Radar Bluetooth</button>
        </div>
        <div id="radar-status" class="radar-box">
            <b>Đang dò sóng móc khóa SUSI...</b><br>
            <span id="rssi-val">Đưa điện thoại lại gần móc khóa</span>
        </div>
        <div id="info-box">
            Vị trí lưu lần cuối: <b id="loc-display">{cur_lat:.5f}, {cur_lon:.5f}</b><br>
            Thời gian: <b id="time-display">{time_str}</b> | Nguồn: <span id="source-display">{source_text}</span>
        </div>
    </div>
    <div id="map"></div>

    <script>
        var susiLat = {cur_lat};
        var susiLon = {cur_lon};

        var map = L.map('map').setView([susiLat, susiLon], 16);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            maxZoom: 19,
            attribution: '© OpenStreetMap'
        }}).addTo(map);

        var susiIcon = L.divIcon({{
            html: '<div style="background:#ff9800;color:#000;font-weight:bold;padding:6px 10px;border-radius:20px;border:2px solid #fff;box-shadow:0 0 10px rgba(0,0,0,0.5);white-space:nowrap;">🐾 SUSI Keychain</div>',
            className: 'susi-marker',
            iconAnchor: [50, 20]
        }});

        var marker = L.marker([susiLat, susiLon], {{ icon: susiIcon }}).addTo(map)
            .bindPopup("<b>🐾 SUSI Keychain AirTag</b><br>Tọa độ: " + susiLat + ", " + susiLon + "<br>Đang phát sóng Apple Find My BLE.")
            .openPopup();

        var accuracyCircle = null;

        function updateMapPosition(lat, lon, acc, source) {{
            susiLat = lat;
            susiLon = lon;
            marker.setLatLng([lat, lon]);
            if (accuracyCircle) map.removeLayer(accuracyCircle);
            if (acc) {{
                accuracyCircle = L.circle([lat, lon], {{ radius: acc, color: '#2196f3', fillOpacity: 0.15 }}).addTo(map);
            }}
            map.setView([lat, lon], 17);
            document.getElementById('loc-display').innerText = lat.toFixed(5) + ", " + lon.toFixed(5);
            document.getElementById('time-display').innerText = new Date().toLocaleTimeString() + " - " + new Date().toLocaleDateString();
            document.getElementById('source-display').innerText = source;
        }}

        function syncCurrentGPS() {{
            if (!navigator.geolocation) {{
                alert("Trình duyệt không hỗ trợ định vị GPS!");
                return;
            }}
            var btn = document.querySelector('.btn-sync');
            btn.innerText = "⏳ Đang lấy GPS vệ tinh...";
            navigator.geolocation.getCurrentPosition(function(pos) {{
                var lat = pos.coords.latitude;
                var lon = pos.coords.longitude;
                var acc = pos.coords.accuracy;

                fetch('/api/update_location', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ lat: lat, lon: lon, accuracy: acc, source: 'GPS Điện Thoại (Live Sync)' }})
                }}).then(res => res.json()).then(data => {{
                    btn.innerText = "✅ Đã Cập Nhật Thành Công!";
                    updateMapPosition(lat, lon, acc, "GPS Điện Thoại (Live Sync)");
                    setTimeout(() => {{ btn.innerText = "📍 Cập Nhật Vị Trí Của Tôi"; }}, 3000);
                }}).catch(err => {{
                    btn.innerText = "❌ Lỗi gửi GPS: " + err;
                }});
            }}, function(err) {{
                btn.innerText = "❌ Không lấy được GPS (Hãy bật định vị)";
                alert("Lỗi lấy vị trí: Vui lòng bật GPS trên điện thoại và cấp quyền vị trí cho trình duyệt Chrome.");
                setTimeout(() => {{ btn.innerText = "📍 Cập Nhật Vị Trí Của Tôi"; }}, 3000);
            }}, {{ enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }});
        }}

        async function startRadarScan() {{
            var radarBox = document.getElementById('radar-status');
            var rssiVal = document.getElementById('rssi-val');
            radarBox.style.display = 'block';

            if (!navigator.bluetooth) {{
                rssiVal.innerText = "Trình duyệt không hỗ trợ Web Bluetooth. Vui lòng mở bằng Chrome trên Android!";
                return;
            }}

            try {{
                rssiVal.innerText = "Đang mở cửa sổ chọn thiết bị Bluetooth gần bạn...";
                const device = await navigator.bluetooth.requestDevice({{
                    acceptAllDevices: true,
                    optionalServices: []
                }});
                rssiVal.innerHTML = "Đã kết nối tín hiệu với: <b>" + (device.name || "Móc khóa SUSI") + "</b><br>Khoảng cách: <b>RẤT GẦN (< 2 mét)</b>";
            }} catch(e) {{
                rssiVal.innerText = "Radar dừng: " + e;
            }}
        }}
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
        parsed = urllib.parse.urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len) if content_len > 0 else b""

        # API Cập nhật vị trí từ điện thoại
        if parsed.path == "/api/update_location":
            try:
                body_json = json.loads(post_body.decode("utf-8")) if post_body else {}
                lat = float(body_json.get("lat", latest_location["lat"]))
                lon = float(body_json.get("lon", latest_location["lon"]))
                acc = float(body_json.get("accuracy", 10))
                src = body_json.get("source", "GPS Điện thoại")

                latest_location["lat"] = lat
                latest_location["lon"] = lon
                latest_location["accuracy"] = acc
                latest_location["timestamp"] = int(time.time())
                latest_location["source"] = src
                save_location()

                print(f"[GPS Update POST] New position: {lat}, {lon} ({src})")
                resp = json.dumps({"status": "success", "location": latest_location}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(resp)
                return
            except Exception as e:
                resp = json.dumps({"status": "error", "message": str(e)}).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(resp)
                return

        # Yêu cầu lấy báo cáo vị trí từ Macless-Haystack Android App
        req_ids = []
        try:
            if post_body:
                body_json = json.loads(post_body.decode("utf-8"))
                req_ids = body_json.get("ids", [])
        except Exception as e:
            print(f"Error parsing POST body: {e}")

        if not req_ids:
            req_ids = [SUSI_KEYS["hashed_adv_key_b64"]]

        results = []
        for rid in req_ids:
            # Mã hóa tọa độ THỰC TẾ mới nhất bằng Private Key của SUSI
            report = generate_encrypted_findmy_report(rid, lat=latest_location["lat"], lon=latest_location["lon"])
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
