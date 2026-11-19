
import fcntl
import json
import sqlite3
import threading
import time
from contextlib import contextmanager

import paho.mqtt.client as mqtt

from config import (
    BASE_DIR,
    MQTT_BROKER,
    MQTT_PORT,
    MQTT_TOPIC,
    MQTT_CA,
    MQTT_CERT,
    MQTT_KEY,
    SENSOR_ID,
)

OUTBOX_DB = BASE_DIR / "mqtt_outbox.sqlite3"
RETRY_CHECK_SECONDS = 3
CONNECT_TIMEOUT_SECONDS = 10
PUBLISH_TIMEOUT_SECONDS = 10

_wake_up = threading.Event()
_worker_lock = threading.Lock()
_worker_started = False


@contextmanager
def _database():
    connection = sqlite3.connect(OUTBOX_DB, timeout=30)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _initialize_outbox():
    with _database() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS mqtt_outbox (
                event_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt REAL NOT NULL DEFAULT 0
            )
        """)

        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(mqtt_outbox)")
        }
        if "next_attempt" not in columns:
            try:
                connection.execute("""
                    ALTER TABLE mqtt_outbox
                    ADD COLUMN next_attempt REAL NOT NULL DEFAULT 0
                """)
            except sqlite3.OperationalError as error:
                if "duplicate column name" not in str(error).lower():
                    raise


def enqueue_event(event):
    _initialize_outbox()
    payload = json.dumps(event, ensure_ascii=False)

    with _database() as connection:
        connection.execute("""
            INSERT OR IGNORE INTO mqtt_outbox (event_id, payload)
            VALUES (?, ?)
        """, (event["event_id"], payload))

    _wake_up.set()


def pending_count():
    _initialize_outbox()
    with _database() as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM mqtt_outbox"
        ).fetchone()[0]


def publish_event(event):
    connected = threading.Event()
    connection_errors = []

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code.is_failure:
            connection_errors.append(str(reason_code))
        connected.set()

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=SENSOR_ID,
        protocol=mqtt.MQTTv311,
    )
    client.on_connect = on_connect
    client.tls_set(
        ca_certs=str(MQTT_CA),
        certfile=str(MQTT_CERT),
        keyfile=str(MQTT_KEY),
    )

    client.connect_async(MQTT_BROKER, MQTT_PORT, keepalive=20)
    client.loop_start()

    try:
        if not connected.wait(CONNECT_TIMEOUT_SECONDS):
            raise TimeoutError("Brak polaczenia z AWS IoT Core")
        if connection_errors:
            raise ConnectionError(connection_errors[0])

        info = client.publish(
            MQTT_TOPIC,
            payload=json.dumps(event, ensure_ascii=False),
            qos=1,
        )
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            raise ConnectionError(f"MQTT publish rc={info.rc}")

        info.wait_for_publish(timeout=PUBLISH_TIMEOUT_SECONDS)
        if not info.is_published():
            raise TimeoutError("Brak potwierdzenia MQTT PUBACK")
    finally:
        client.disconnect()
        client.loop_stop()


def _send_one_pending():
    _initialize_outbox()

    with OUTBOX_DB.open("rb") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            with _database() as connection:
                row = connection.execute("""
                    SELECT event_id, payload, attempts
                    FROM mqtt_outbox
                    WHERE next_attempt <= ?
                    ORDER BY rowid
                    LIMIT 1
                """, (time.time(),)).fetchone()

            if row is None:
                return False

            event_id, payload, attempts = row
            try:
                publish_event(json.loads(payload))
            except Exception as error:
                delay = min(5 * (2 ** min(attempts, 6)), 300)
                with _database() as connection:
                    connection.execute("""
                        UPDATE mqtt_outbox
                        SET attempts = attempts + 1, next_attempt = ?
                        WHERE event_id = ?
                    """, (time.time() + delay, event_id))
                print(
                    f"[MQTT] Blad wysylki {event_id}: {error}. "
                    f"Ponowienie za okolo {delay} s.",
                    flush=True,
                )
                return False

            with _database() as connection:
                connection.execute(
                    "DELETE FROM mqtt_outbox WHERE event_id = ?",
                    (event_id,),
                )
            print(f"[MQTT] Wyslano {event_id}", flush=True)
            return True
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _retry_loop():
    while True:
        try:
            while _send_one_pending():
                pass
        except Exception as error:
            print(f"[MQTT] Blad kolejki: {error}", flush=True)

        _wake_up.wait(timeout=RETRY_CHECK_SECONDS)
        _wake_up.clear()


def start_retry_worker():
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        threading.Thread(
            target=_retry_loop,
            name="mqtt-retry-worker",
            daemon=True,
        ).start()
        _worker_started = True


def wake_retry_worker():
    _wake_up.set()
