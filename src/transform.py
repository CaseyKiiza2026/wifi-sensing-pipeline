import re
from datetime import datetime, timezone

VALID_BANDS = {"2.4GHz", "5GHz", "6GHz"}
VALID_SECURITY = {"Open","WEP","WPA","WPA2","WPA3","WPA2/WPA3"}

mac_regex = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

def normalize_band(band):
    band = band.replace(" ", "").lower()
    if band.startswith("2.4"):
        return "2.4GHz"
    if band.startswith("5"):
        return "5GHz"
    if band.startswith("6"):
        return "6GHz"
    return None

#def valid_band(band):
def channel_in_possible_range(channel: int, band: str) -> bool:
    if band == "2.4GHz":
        return 1 <= channel <= 14
    if band == "5GHz":
        return 1 <= channel <= 200   # wide tolerance
    if band == "6GHz":
        return 1 <= channel <= 233
    return False

#def valid_security(sec):
def channel_is_standard(channel: int, band: str) -> bool:
    if band == "2.4GHz":
        return 1 <= channel <= 14

    if band == "5GHz":
        return (
            36 <= channel <= 64 or
            100 <= channel <= 144 or
            149 <= channel <= 165 or
            169 <= channel <= 177
        )

    if band == "6GHz":
        return 1 <= channel <= 233  # keeping broad until you map exact 6E blocks

    return False

def normalize_security(sec):
    sec = sec.upper()
    if "WPA3" in sec and "WPA2" in sec:
        return "WPA2/WPA3"
    if "WPA3" in sec:
        return "WPA3"
    if "WPA2" in sec:
        return "WPA2"
    if "WPA" in sec:
        return "WPA"
    if "WEP" in sec:
        return "WEP"
    if "OPEN" in sec:
        return "Open"
    return None


def preprocess(scan):
    ts_iso = to_iso(scan.get("timestamp"))
    if ts_iso is None:
        return None
def to_iso(ts):
    if ts is None or ts == "":
        return None  # strict: missing is invalid

    if isinstance(ts, datetime):
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()

    if isinstance(ts, str):
        s = ts.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            return None  # strict: bad is invalid

    return None
    # BSSID validation
    bssid = scan.get("bssid")
    if not bssid or not mac_regex.match(bssid):
        return None

    # RSSI validation
    try:
        rssi = int(scan.get("rssi"))
        if not (-100 <= rssi <= 0):
            return None
    except:
        return None
    
    # Normalize band
    band = normalize_band(scan.get("band",""))
    if not band:
        return None

    # Channel + Validate channel for band
    try:
        channel = int(scan.get("channel"))
    except:
        return None
   
    
    # Reject impossible physics
    if not channel_in_possible_range(channel, band):
        return None
    

    # Normalize security
    security = normalize_security(scan.get("security",""))
    if not security:
        return None

    cleaned = {
    "ssid": scan.get("ssid",""),
    "bssid": bssid.lower(),
    "rssi": rssi,
    "channel": channel,
    "band": band,
    "security": security,
    "channel_valid": channel_valid,   # ← truth label
    "timestamp": ts_iso
}


    return cleaned
