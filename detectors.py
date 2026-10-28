from collections import defaultdict, deque
from time import monotonic, time

from scapy.layers.dot11 import (
    Dot11,
    Dot11Elt,
    Dot11Beacon,
    Dot11ProbeResp,
    Dot11Deauth,
    Dot11Disas,
)

from config import (
    WINDOW_SECONDS,
    DEAUTH_THRESHOLD,
    PROBE_THRESHOLD,
    ALERT_COOLDOWN,
    TRUSTED_APS,
    TRUSTED_AP_PROFILES,
    EVENT_LOG,
)

from events import create_event, emit_event


deauth_events = defaultdict(deque)
probe_events = defaultdict(deque)

last_deauth_alert = {}
last_probe_alert = {}
last_rogue_alert = {}
last_mac_anomaly_alert = {}


def normalize_mac(mac):
    if not mac:
        return None

    return mac.lower()


def get_ssid(packet):
    element = packet.getlayer(Dot11Elt)

    while element is not None:
        if getattr(element, "ID", None) == 0:
            try:
                return element.info.decode(
                    "utf-8",
                    errors="replace",
                )
            except Exception:
                return ""

        element = element.payload.getlayer(
            Dot11Elt
        )

    return None


def get_advertised_channel(packet):
    element = packet.getlayer(Dot11Elt)

    while element is not None:
        if getattr(element, "ID", None) == 3:
            try:
                if element.info:
                    return int(element.info[0])
            except Exception:
                return None

        element = element.payload.getlayer(
            Dot11Elt
        )

    return None


def frequency_to_channel(frequency):
    if not frequency:
        return None

    try:
        frequency = int(frequency)
    except (TypeError, ValueError):
        return None

    if frequency == 2484:
        return 14

    if 2412 <= frequency <= 2472:
        return (frequency - 2407) // 5

    if 5000 <= frequency <= 5900:
        return (frequency - 5000) // 5

    return None


def get_capture_channel(packet):
    frequency = getattr(
        packet,
        "ChannelFrequency",
        None,
    )

    return frequency_to_channel(frequency)


def get_radio_info(packet):
    channel = get_advertised_channel(packet)

    if channel is None:
        channel = get_capture_channel(packet)

    rssi = getattr(
        packet,
        "dBm_AntSignal",
        None,
    )

    try:
        if rssi is not None:
            rssi = int(rssi)
    except (TypeError, ValueError):
        rssi = None

    return channel, rssi


def get_frame_type(packet):
    if packet.haslayer(Dot11Beacon):
        return "Beacon"

    if packet.haslayer(Dot11ProbeResp):
        return "Probe Response"

    if packet.haslayer(Dot11Deauth):
        return "Deauthentication"

    if packet.haslayer(Dot11Disas):
        return "Disassociation"

    return "Unknown"


def get_immediate_detection_latency_ms(packet):
    packet_time = getattr(
        packet,
        "time",
        None,
    )

    if packet_time is None:
        return None

    try:
        latency = (
            time() - float(packet_time)
        ) * 1000

        return round(
            max(latency, 0),
            2,
        )

    except (TypeError, ValueError):
        return None


def detect_deauth_flood(packet):
    if not packet.haslayer(Dot11):
        return

    if not (
        packet.haslayer(Dot11Deauth)
        or packet.haslayer(Dot11Disas)
    ):
        return

    dot11 = packet[Dot11]

    source_mac = normalize_mac(
        dot11.addr2
    )

    destination_mac = normalize_mac(
        dot11.addr1
    )

    bssid = normalize_mac(
        dot11.addr3
    )

    if not bssid:
        bssid = source_mac

    if not bssid:
        return

    reason = None

    if packet.haslayer(Dot11Deauth):
        reason = getattr(
            packet[Dot11Deauth],
            "reason",
            None,
        )

    elif packet.haslayer(Dot11Disas):
        reason = getattr(
            packet[Dot11Disas],
            "reason",
            None,
        )

    now = monotonic()

    events = deauth_events[bssid]
    events.append(now)

    while (
        events
        and now - events[0]
        > WINDOW_SECONDS
    ):
        events.popleft()

    print(
        f"[DEAUTH] "
        f"src={source_mac} "
        f"dst={destination_mac} "
        f"bssid={bssid} "
        f"reason={reason} "
        f"count={len(events)}/"
        f"{DEAUTH_THRESHOLD}"
    )

    if len(events) < DEAUTH_THRESHOLD:
        return

    previous_alert = (
        last_deauth_alert.get(
            bssid,
            0,
        )
    )

    if (
        now - previous_alert
        < ALERT_COOLDOWN
    ):
        return

    last_deauth_alert[bssid] = now

    detection_latency_ms = round(
        (now - events[0]) * 1000,
        2,
    )

    event = create_event(
        "DEAUTH_FLOOD",
        "high",
        bssid=bssid,
        source_mac=source_mac,
        destination_mac=destination_mac,
        reason=reason,
        frame_count=len(events),
        window_seconds=WINDOW_SECONDS,
        detection_latency_ms=(
            detection_latency_ms
        ),
    )

    emit_event(event)

    print()
    print("!" * 70)
    print(
        "[ALERT] Podejrzenie ataku "
        "deauthentication"
    )
    print(
        f"BSSID: {bssid}"
    )
    print(
        "Liczba ramek "
        "deauthentication/disassociation: "
        f"{len(events)} "
        f"w czasie {WINDOW_SECONDS} s"
    )
    print(
        "Detection latency: "
        f"{detection_latency_ms} ms"
    )
    print(
        "Zdarzenie zapisano do: "
        f"{EVENT_LOG}"
    )
    print("!" * 70)
    print()


def detect_probe_flood(packet):
    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    if (
        dot11.type != 0
        or dot11.subtype != 4
    ):
        return

    source_mac = normalize_mac(
        dot11.addr2
    )

    if not source_mac:
        return

    now = monotonic()

    events = probe_events[source_mac]
    events.append(now)

    while (
        events
        and now - events[0]
        > WINDOW_SECONDS
    ):
        events.popleft()

    ssid = get_ssid(packet)

    print(
        f"[PROBE] "
        f"src={source_mac} "
        f"ssid={ssid!r} "
        f"count={len(events)}/"
        f"{PROBE_THRESHOLD}"
    )

    if len(events) < PROBE_THRESHOLD:
        return

    previous_alert = (
        last_probe_alert.get(
            source_mac,
            0,
        )
    )

    if (
        now - previous_alert
        < ALERT_COOLDOWN
    ):
        return

    last_probe_alert[source_mac] = now

    detection_latency_ms = round(
        (now - events[0]) * 1000,
        2,
    )

    channel, rssi = get_radio_info(
        packet
    )

    event = create_event(
        "PROBE_FLOOD",
        "medium",
        source_mac=source_mac,
        ssid=ssid,
        channel=channel,
        rssi=rssi,
        frame_count=len(events),
        window_seconds=WINDOW_SECONDS,
        detection_latency_ms=(
            detection_latency_ms
        ),
    )

    emit_event(event)

    print()
    print("!" * 70)
    print(
        "[ALERT] Podejrzenie ataku "
        "Probe Flood"
    )
    print(
        f"Source MAC: {source_mac}"
    )
    print(
        "Liczba ramek Probe Request: "
        f"{len(events)} "
        f"w czasie {WINDOW_SECONDS} s"
    )
    print(
        "Detection latency: "
        f"{detection_latency_ms} ms"
    )
    print(
        "Zdarzenie zapisano do: "
        f"{EVENT_LOG}"
    )
    print("!" * 70)
    print()


def detect_rogue_ap(packet):
    if not packet.haslayer(Dot11):
        return

    if not (
        packet.haslayer(Dot11Beacon)
        or packet.haslayer(Dot11ProbeResp)
    ):
        return

    dot11 = packet[Dot11]

    ssid = get_ssid(packet)

    if not ssid:
        return

    if ssid not in TRUSTED_APS:
        return

    bssid = normalize_mac(
        dot11.addr3
    )

    if not bssid:
        bssid = normalize_mac(
            dot11.addr2
        )

    if not bssid:
        return

    trusted_bssids = {
        normalize_mac(mac)
        for mac
        in TRUSTED_APS[ssid]
    }

    if bssid in trusted_bssids:
        return

    now = monotonic()

    alert_key = (
        ssid,
        bssid,
    )

    previous_alert = (
        last_rogue_alert.get(
            alert_key,
            0,
        )
    )

    if (
        now - previous_alert
        < ALERT_COOLDOWN
    ):
        return

    last_rogue_alert[
        alert_key
    ] = now

    channel, rssi = get_radio_info(
        packet
    )

    source_mac = normalize_mac(
        dot11.addr2
    )

    frame_type = get_frame_type(
        packet
    )

    detection_latency_ms = (
        get_immediate_detection_latency_ms(
            packet
        )
    )

    event = create_event(
        "ROGUE_AP",
        "high",
        ssid=ssid,
        bssid=bssid,
        source_mac=source_mac,
        frame_type=frame_type,
        channel=channel,
        rssi=rssi,
        trusted_bssids=sorted(
            trusted_bssids
        ),
        detection_latency_ms=(
            detection_latency_ms
        ),
    )

    emit_event(event)

    print()
    print("!" * 70)
    print(
        "[ALERT] Podejrzenie "
        "Rogue AP / Evil Twin"
    )
    print(
        f"SSID: {ssid}"
    )
    print(
        f"Nieznany BSSID: {bssid}"
    )
    print(
        "Zaufane BSSID: "
        f"{', '.join(sorted(trusted_bssids))}"
    )
    print(
        f"Typ ramki: {frame_type}"
    )
    print(
        "Detection latency: "
        f"{detection_latency_ms} ms"
    )
    print(
        "Zdarzenie zapisano do: "
        f"{EVENT_LOG}"
    )
    print("!" * 70)
    print()


def detect_mac_identity_anomaly(packet):
    if not packet.haslayer(Dot11):
        return

    if not (
        packet.haslayer(Dot11Beacon)
        or packet.haslayer(Dot11ProbeResp)
    ):
        return

    dot11 = packet[Dot11]

    bssid = normalize_mac(
        dot11.addr3
    )

    if not bssid:
        bssid = normalize_mac(
            dot11.addr2
        )

    if not bssid:
        return

    profiles = {
        normalize_mac(mac): profile
        for mac, profile
        in TRUSTED_AP_PROFILES.items()
    }

    profile = profiles.get(
        bssid
    )

    if profile is None:
        return

    expected_ssid = profile.get(
        "ssid"
    )

    expected_channel = profile.get(
        "channel"
    )

    observed_ssid = get_ssid(
        packet
    )

    observed_channel = (
        get_advertised_channel(
            packet
        )
    )

    capture_channel = (
        get_capture_channel(
            packet
        )
    )

    _, rssi = get_radio_info(
        packet
    )

    anomalies = []

    if (
        expected_ssid is not None
        and observed_ssid is not None
        and observed_ssid
        != expected_ssid
    ):
        anomalies.append(
            "ssid"
        )

    if (
        expected_channel is not None
        and observed_channel is not None
        and observed_channel
        != expected_channel
    ):
        anomalies.append(
            "channel"
        )

    if not anomalies:
        return

    now = monotonic()

    alert_key = (
        bssid,
        tuple(anomalies),
        observed_ssid,
        observed_channel,
    )

    previous_alert = (
        last_mac_anomaly_alert.get(
            alert_key,
            0,
        )
    )

    if (
        now - previous_alert
        < ALERT_COOLDOWN
    ):
        return

    last_mac_anomaly_alert[
        alert_key
    ] = now

    source_mac = normalize_mac(
        dot11.addr2
    )

    frame_type = get_frame_type(
        packet
    )

    detection_latency_ms = (
        get_immediate_detection_latency_ms(
            packet
        )
    )

    event = create_event(
        "MAC_IDENTITY_ANOMALY",
        "high",
        bssid=bssid,
        source_mac=source_mac,
        frame_type=frame_type,
        expected_ssid=expected_ssid,
        observed_ssid=observed_ssid,
        expected_channel=expected_channel,
        observed_channel=observed_channel,
        capture_channel=capture_channel,
        rssi=rssi,
        anomalies=anomalies,
        detection_latency_ms=(
            detection_latency_ms
        ),
    )

    emit_event(event)

    print()
    print("!" * 70)
    print(
        "[ALERT] Anomalia tożsamości AP "
        "/ możliwy MAC spoofing"
    )
    print(
        f"BSSID: {bssid}"
    )

    if "ssid" in anomalies:
        print(
            "SSID: oczekiwano "
            f"{expected_ssid!r}, "
            "otrzymano "
            f"{observed_ssid!r}"
        )

    if "channel" in anomalies:
        print(
            "Kanał: oczekiwano "
            f"{expected_channel}, "
            "otrzymano "
            f"{observed_channel}"
        )

    print(
        "Detection latency: "
        f"{detection_latency_ms} ms"
    )
    print(
        "Zdarzenie zapisano do: "
        f"{EVENT_LOG}"
    )
    print("!" * 70)
    print()
