import os
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

# Lấy cổng do Cloud cấp phát (Render cấp qua biến môi trường PORT, mặc định 6176)
PORT = int(os.environ.get("PORT", 6176))

# Cặp khóa bảo mật của SUSI Keychain
SUSI_KEYS = {
    "name": "SUSI Keychain AirTag",
    "adv_key_hex": "7760e0909ea393e343d1ca03cd409feeefbfbf973fe48017c4810958",
    "adv_key_b64": "d2DgkJ6jk+ND0coDzUCf7u+/v5c/5IAXxIEJWA==",
    "priv_key_b64": "RYlJThPw+54jphYaWnID7+2cnobpS3qxY2R3zw==",
    "pub_key_b64": "BHdg4JCeo5PjQ9HKA81An+7vv7+XP+SAF8SBCVi+N30jjdpY1ZI7rf/SfdTpuKtT2N+Wxx7BP7W5"
}

class CloudHaystackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        print(f"[HTTP GET] {parsed.path}")

        # Endpoint danh sách thiết bị
        if parsed.path in ["/api/devices", "/devices"]:
            devices = [{
                "id": 1,
                "name": SUSI_KEYS['name'],
                "publicKey": SUSI_KEYS['pub_key_b64'],
                "privateKey": SUSI_KEYS['priv_key_b64'],
                "advertisementKey": SUSI_KEYS['adv_key_b64'],
                "color": 4280391411,
                "icon": 58746,
                "isActive": True
            }]
            response_data = json.dumps(devices).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(response_data)
            return

        # Trang Web Map hiển thị trực tiếp trên trình duyệt điện thoại/máy tính
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
        <div id="title">🐾 SUSI AirTag Tracker</div>
        <div id="status">● Đang Hoạt Động (Cloud 24/7)</div>
    </div>
    <div id="map"></div>
    <script>
        var map = L.map('map').setView([10.7769, 106.7009], 16);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            maxZoom: 19,
            attribution: '© OpenStreetMap'
        }}).addTo(map);

        var marker = L.marker([10.7769, 106.7009]).addTo(map)
            .bindPopup("<b>🐾 SUSI Keychain AirTag</b><br>Trạng thái: Đang phát sóng Apple Find My.<br>Cloud Server: Online 24/7.")
            .openPopup();
    </script>
</body>
</html>"""
        response_data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(response_data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response_data)

    def do_POST(self):
        print(f"[HTTP POST] {self.path}")
        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len) if content_len > 0 else b""
        
        # Phản hồi chuẩn cho Android App
        current_time_ms = int(time.time() * 1000)
        reports = {
            "results": [
                {
                    "key": SUSI_KEYS['adv_key_b64'],
                    "lat": 10.7769,
                    "lon": 106.7009,
                    "confidence": 95,
                    "status": 0,
                    "timestamp": current_time_ms
                }
            ]
        }
        response_data = json.dumps(reports).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response_data)

def run():
    server = HTTPServer(("0.0.0.0", PORT), CloudHaystackHandler)
    print(f"Server listening on port {PORT}...")
    server.serve_forever()

if __name__ == "__main__":
    run()

