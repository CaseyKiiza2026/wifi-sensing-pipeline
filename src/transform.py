import re
from datetime import datetime, timezone

VALID_BANDS = {"2.4GHz", "5GHz", "6GHz"}
VALID_SECURITY = {"Open","WEP","WPA","WPA2","WPA3","WPA2/WPA3"}

mac_regex = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

def normalize_band(band):
    band = (band or "").replace(" ", "").lower()
    if band.startswith("2.4"):
        return "2.4GHz"
    if band.startswith("5"):
        return "5GHz"
    if band.startswith("6"):
        return "6GHz"
    return None


def channel_in_possible_range(channel: int, band: str) -> bool:
    if band == "2.4GHz":
        return 1 <= channel <= 14
    if band == "5GHz":
        return 1 <= channel <= 200   # wide tolerance
    if band == "6GHz":
        return 1 <= channel <= 233
    return False


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
    sec = (sec or "").upper()
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

def validate_bssid(scan):
    bssid = scan.get("bssid")
    if not bssid or not mac_regex.match(bssid):
        return None
    return bssid.lower()

def validate_rssi(scan):
    try:
        rssi = int(scan.get("rssi"))
        if -100 <= rssi <= 0:
            return rssi
    except (TypeError, ValueError):
        pass
    return None

def validate_band(scan):
    band = normalize_band(scan.get("band", ""))
    return band  # already returns None if invalid

def validate_channel(scan, band):
    try:
        channel = int(scan.get("channel"))
    except (TypeError, ValueError):
        return None, None  # (channel, channel_valid)

    if not channel_in_possible_range(channel, band):
        return None, None

    channel_valid = channel_is_standard(channel, band)
    return channel, channel_valid

def validate_security(scan):
    return normalize_security(scan.get("security", ""))

def preprocess(scan):
    ts_iso = to_iso(scan.get("timestamp"))
    if ts_iso is None:
        return None

    bssid = validate_bssid(scan)
    if bssid is None:
        return None

    rssi = validate_rssi(scan)
    if rssi is None:
        return None

    band = validate_band(scan)
    if band is None:
        return None

    channel, channel_valid = validate_channel(scan, band)
    if channel is None:
        return None

    security = validate_security(scan)
    if security is None:
        return None

    return {
        "ssid": scan.get("ssid", ""),
        "bssid": bssid,
        "rssi": rssi,
        "channel": channel,
        "band": band,
        "security": security,
        "channel_valid": channel_valid,
        "timestamp": ts_iso,
    }

  

