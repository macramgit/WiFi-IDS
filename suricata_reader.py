import json
import os
import time
from pathlib import Path

from events import create_event, emit_event


EVE_FILE = Path("/var/log/suricata/eve.json")
COOLDOWN_SECONDS = 30
POLL_INTERVAL = 0.2

last_alerts = {}


def map_severity(value):
    return {
        1: "high",
        2: "medium",
        3: "low",
    }.get(value, "medium")


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


def process_line(line):
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return

    if data.get("event_type") != "alert":
        return

    normalized = normalize_alert(data)

    if not should_emit(normalized):
        return

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

    print(
        json.dumps(event, indent=2, ensure_ascii=False),
        flush=True,
    )


def open_eve(start_at_end):
    while True:
        try:
            file = EVE_FILE.open(
                "r",
                encoding="utf-8",
                errors="replace",
            )

            if start_at_end:
                file.seek(0, os.SEEK_END)

            stat = os.fstat(file.fileno())

            print(
                f"[SURICATA] Otwarto {EVE_FILE} "
                f"(inode={stat.st_ino}, "
                f"start={'EOF' if start_at_end else 'BOF'})",
                flush=True,
            )

            return file

        except FileNotFoundError:
            print(
                f"[SURICATA] Oczekiwanie na {EVE_FILE}...",
                flush=True,
            )
            time.sleep(1)


def file_was_replaced(file):
    try:
        path_stat = EVE_FILE.stat()
        fd_stat = os.fstat(file.fileno())
    except FileNotFoundError:
        return False

    return (
        path_stat.st_dev != fd_stat.st_dev
        or path_stat.st_ino != fd_stat.st_ino
    )


def file_was_truncated(file):
    try:
        return EVE_FILE.stat().st_size < file.tell()
    except (FileNotFoundError, OSError):
        return False


def follow_eve():
    # Przy starcie pomijamy stare wpisy.
    file = open_eve(start_at_end=True)

    try:
        while True:
            line = file.readline()

            if line:
                process_line(line)
                continue

            # Typowa rotacja: eve.json zostaje podmieniony na nowy plik.
            if file_was_replaced(file):
                print(
                    "[SURICATA] Wykryto rotację eve.json.",
                    flush=True,
                )

                file.close()

                # Nowy plik czytamy od początku, aby nie zgubić wpisów
                # zapisanych między rotacją a ponownym otwarciem.
                file = open_eve(start_at_end=False)
                continue

            # Wariant copytruncate: inode zostaje, ale rozmiar maleje.
            if file_was_truncated(file):
                print(
                    "[SURICATA] Wykryto skrócenie eve.json.",
                    flush=True,
                )
                file.seek(0)
                continue

            time.sleep(POLL_INTERVAL)

    finally:
        file.close()


if __name__ == "__main__":
    follow_eve()
