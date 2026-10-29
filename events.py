import json
from datetime import datetime, timezone

from config import SENSOR_ID, EVENT_LOG
from mqtt_transport import publish_event
import uuid

SCHEMA_VERSION = "1.0"


def create_event(event_type, severity, **data):
    event = {
        "event_id": str(uuid.uuid4()),
	"schema_version": SCHEMA_VERSION,
        "sensor_id": SENSOR_ID,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "event_type": event_type,
        "severity": severity,
    }

    event.update(data)

    return event


def save_event(event):
    with EVENT_LOG.open(
        "a",
        encoding="utf-8"
    ) as file:
        file.write(
            json.dumps(
                event,
                ensure_ascii=False
            ) + "\n"
        )


def emit_event(event):
    save_event(event)

    try:
        publish_event(event)
    except Exception as error:
        print(
            f"[MQTT] Nie udało się wysłać "
            f"zdarzenia: {error}"
        )
