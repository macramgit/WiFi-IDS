import json
import uuid
from datetime import datetime, timezone

from config import SENSOR_ID, EVENT_LOG
from mqtt_transport import enqueue_event, start_retry_worker

SCHEMA_VERSION = "1.0"


def create_event(event_type, severity, **data):
    event = {
        "event_id": str(uuid.uuid4()),
        "schema_version": SCHEMA_VERSION,
        "sensor_id": SENSOR_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "severity": severity,
    }
    event.update(data)
    return event


def save_event(event):
    with EVENT_LOG.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, ensure_ascii=False) + "\n")


def emit_event(event):
    enqueue_event(event)
    save_event(event)


start_retry_worker()
