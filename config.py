from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

INTERFACE = "wlan0"
SENSOR_ID = "sensor-01"

EVENT_LOG = BASE_DIR / "events.jsonl"

WINDOW_SECONDS = 5

DEAUTH_THRESHOLD = 10
PROBE_THRESHOLD = 50

ALERT_COOLDOWN = 10


TRUSTED_APS = {
    "NETIASPOT-qCr7": {
        "64:bf:6b:7f:4d:9c",
    },
    "NETIASPOT-qCr7_Plus": {
        "58:ea:1f:63:8f:88",
    },
    "UPCE67BF3E": {
        "54:67:51:9c:ca:d9",
	"54:67:51:9c:ca:cf",
    },
    "UPC508485575": {
        "8c:5b:f0:a0:29:b4",
    },

}


TRUSTED_AP_PROFILES = {
    "64:bf:6b:7f:4d:9c": {
        "ssid": "NETIASPOT-qCr7",
        "channel": 6,
    },
    "58:ea:1f:63:8f:88": {
        "ssid": "NETIASPOT-qCr7_Plus",
        "channel": 6,
    },
    "54:67:51:9c:ca:d9": {
        "ssid": "UPCE67BF3E",
        "channel": 11,
    },

    "8c:5b:f0:a0:29:b4": {
        "ssid": "UPC508485575",
        "channel": 100,
    }
}


MQTT_BROKER = (
    "a317a4x0vu33xc-ats.iot.us-east-1.amazonaws.com"
)

MQTT_PORT = 8883
MQTT_TOPIC = "wifi-ids/events"

MQTT_CA = BASE_DIR / "certs" / "AmazonRootCA1.pem"
MQTT_CERT = (
    BASE_DIR
    / "certs"
    / "sensor01-certificate.pem.crt"
)
MQTT_KEY = (
    BASE_DIR
    / "certs"
    / "sensor01-private.pem.key"
)
