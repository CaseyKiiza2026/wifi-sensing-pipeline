CREATE TABLE IF NOT EXISTS wifi_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    ssid TEXT,

    bssid TEXT NOT NULL,

    rssi INTEGER NOT NULL CHECK (rssi BETWEEN -100 AND 0),

    channel INTEGER NOT NULL CHECK (channel BETWEEN 1 AND 233),

    band TEXT NOT NULL CHECK (band IN ('2.4GHz','5GHz','6GHz')),

    security TEXT NOT NULL CHECK (
        security IN ('Open','WEP','WPA','WPA2','WPA3','WPA2/WPA3')
    ),

    timestamp TEXT NOT NULL,

    UNIQUE(bssid, timestamp)
);
