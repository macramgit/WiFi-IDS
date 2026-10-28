import json
import time

from events import create_event, emit_event


EVE_FILE = "/var/log/suricata/eve.json"

COOLDOWN_SECONDS = 30
last_alerts = {}


def map_severity(value):
    mapping = {
        1: "high",
        2: "medium",
        3: "low",
    }

    return mapping.get(value, "medium")


def normalize_alert(data):
    alert = data.get("alert", {})

    return {
        "event_type": "SURICATA_ALERT",
        "severity": map_severity(alert.get("severity")),
        "source_ip": data.get("src_ip"),
        "destination_ip": data.get("dest_ip"),
        "protocol": data.get("proto"),
        "signature": alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "category": alert.get("category"),
        "suricata_timestamp": data.get("timestamp"),
    }


def should_emit(event):
    key = (
        event.get("signature_id"),
        event.get("source_ip"),
        event.get("destination_ip"),
    )

    now = time.monotonic()
    last_time = last_alerts.get(key)

    if last_time is not None and now - last_time < COOLDOWN_SECONDS:
        return False

    last_alerts[key] = now
    return True


def follow_eve():
    with open(EVE_FILE, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(0.2)
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if data.get("event_type") != "alert":
                continue

            normalized = normalize_alert(data)

            if not should_emit(normalized):
                continue

            event = create_event(
                normalized["event_type"],
                normalized["severity"],
                source_ip=normalized["source_ip"],
                destination_ip=normalized["destination_ip"],
                protocol=normalized["protocol"],
                signature=normalized["signature"],
                signature_id=normalized["signature_id"],
                category=normalized["category"],
                suricata_timestamp=normalized["suricata_timestamp"],
            )

            emit_event(event)

            print(json.dumps(event, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    follow_eve()
