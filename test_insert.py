import sqlite3

conn = sqlite3.connect("wifi.db")
c = conn.cursor()

try:
    c.execute("""
    INSERT INTO wifi_scans (ssid,bssid,rssi,channel,band,security,timestamp)
    VALUES ('TestNetwork','AA:BB:CC:DD:EE:FF',-200,6,'5GHz','WPA2','2026-02-14T20:00:00Z')
    """)
    conn.commit()
    print("INSERT SUCCEEDED (THIS IS BAD)")
except Exception as e:
    print("Insert failed as expected:")
    print(e)

conn.close()
