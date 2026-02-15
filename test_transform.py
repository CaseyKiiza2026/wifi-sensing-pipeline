from datetime import datetime, timezone
from src.transform import preprocess

tests = [
    ("valid_24", {
        "ssid": "HomeNetwork",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "rssi": -65,
        "channel": 6,
        "band": "2.4GHz",
        "security": "WPA2",
        "timestamp": "2024-02-15T10:30:00Z",
    }, True),

    ("valid_5", {
        "ssid": "Office_5G",
        "bssid": "11:22:33:44:55:66",
        "rssi": -70,
        "channel": 36,
        "band": "5GHz",
        "security": "WPA3",
        "timestamp": datetime.now(timezone.utc),
    }, True),

    ("bad_bssid", {
        "ssid": "BadMAC",
        "bssid": "ZZZZZZ",
        "rssi": -60,
        "channel": 11,
        "band": "2.4",
        "security": "WPA2",
        "timestamp": "2024-02-15T10:30:00Z",
    }, False),

    ("rssi_out_of_range", {
        "ssid": "TooStrong",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "rssi": 50,
        "channel": 6,
        "band": "2.4GHz",
        "security": "WPA2",
        "timestamp": "2024-02-15T10:30:00Z",
    }, False),

    ("channel_impossible", {
        "ssid": "BadChannel",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "rssi": -65,
        "channel": 500,
        "band": "2.4GHz",
        "security": "WPA2",
        "timestamp": "2024-02-15T10:30:00Z",
    }, False),

    ("mixed_security", {
        "ssid": "ModernAP",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "rssi": -55,
        "channel": 149,
        "band": "5 GHz",
        "security": "wpa2/wpa3 mixed",
        "timestamp": "2024-02-15T10:30:00Z",
    }, True),

    ("missing_timestamp", {
        "ssid": "NoTime",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "rssi": -65,
        "channel": 6,
        "band": "2.4GHz",
        "security": "WPA2",
        "timestamp": None,
    }, False),
]

passed = 0

for name, scan, should_pass in tests:
    try:
        out = preprocess(scan)
        ok = out is not None
        if ok == should_pass:
            print(f"✅ {name}")
            passed += 1
        else:
            print(f"❌ {name} (expected {should_pass}, got {ok}) -> {out}")
    except Exception as e:
        print(f"💥 {name} crashed: {e}")

print(f"\n{passed}/{len(tests)} tests passed")
