from collections import defaultdict, deque
from time import monotonic, time

from scapy.layers.dot11 import (
    Dot11,
    Dot11Elt,
    Dot11Beacon,
    Dot11ProbeReq,
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
)
from events import create_event, emit_event


deauth_events = defaultdict(deque)
probe_events = defaultdict(deque)

last_deauth_alert = {}
last_probe_alert = {}
last_rogue_alert = {}
last_mac_alert = {}

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def normalize_mac(value):
    if not value:
        return None
    return str(value).lower()


def get_ssid(packet):
    elt = packet.getlayer(Dot11Elt)

    while elt is not None:
        if getattr(elt, "ID", None) == 0:
            raw = getattr(elt, "info", b"")

            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="ignore")

            return str(raw)

        payload = getattr(elt, "payload", None)
        if payload is None:
            break

        elt = payload.getlayer(Dot11Elt)

    return None


def get_advertised_channel(packet):
    elt = packet.getlayer(Dot11Elt)

    while elt is not None:
        if getattr(elt, "ID", None) == 3:
            raw = getattr(elt, "info", b"")

            if isinstance(raw, bytes) and raw:
                return int(raw[0])

            try:
                return int(raw)
            except (TypeError, ValueError):
                return None

        payload = getattr(elt, "payload", None)
        if payload is None:
            break

        elt = payload.getlayer(Dot11Elt)

    return None


def frequency_to_channel(freq):
    if freq is None:
        return None

    try:
        freq = int(freq)
    except (TypeError, ValueError):
        return None

    if freq == 2484:
        return 14

    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5

    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5

    return None


def get_capture_channel(packet):
    radiotap = packet.getlayer("RadioTap")

    if radiotap is None:
        return None

    freq = getattr(radiotap, "ChannelFrequency", None)
    return frequency_to_channel(freq)


def get_radio_info(packet):
    radiotap = packet.getlayer("RadioTap")

    if radiotap is None:
        return {
            "rssi": None,
            "frequency": None,
            "capture_channel": None,
        }

    rssi = getattr(radiotap, "dBm_AntSignal", None)
    frequency = getattr(radiotap, "ChannelFrequency", None)

    try:
        if rssi is not None:
            rssi = int(rssi)
    except (TypeError, ValueError):
        rssi = None

    try:
        if frequency is not None:
            frequency = int(frequency)
    except (TypeError, ValueError):
        frequency = None

    return {
        "rssi": rssi,
        "frequency": frequency,
        "capture_channel": frequency_to_channel(frequency),
    }


def get_frame_type(packet):
    if packet.haslayer(Dot11Beacon):
        return "Beacon"

    if packet.haslayer(Dot11ProbeResp):
        return "Probe Response"

    if packet.haslayer(Dot11ProbeReq):
        return "Probe Request"

    if packet.haslayer(Dot11Deauth):
        return "Deauthentication"

    if packet.haslayer(Dot11Disas):
        return "Disassociation"

    return "Unknown"


def get_immediate_detection_latency_ms(packet):
    packet_time = getattr(packet, "time", None)

    if packet_time is None:
        return None

    try:
        latency = (time() - float(packet_time)) * 1000
        return round(max(latency, 0), 2)
    except (TypeError, ValueError):
        return None


def get_sequence_number(packet):
    dot11 = packet.getlayer(Dot11)

    if dot11 is None:
        return None

    sc = getattr(dot11, "SC", None)

    if sc is None:
        return None

    try:
        return (int(sc) >> 4) & 0x0FFF
    except (TypeError, ValueError):
        return None


def get_fragment_number(packet):
    dot11 = packet.getlayer(Dot11)

    if dot11 is None:
        return None

    sc = getattr(dot11, "SC", None)

    if sc is None:
        return None

    try:
        return int(sc) & 0x000F
    except (TypeError, ValueError):
        return None


def make_frame_identity(packet):
    """
    Identyfikator logicznej ramki 802.11 używany tylko do odrzucania
    retransmisji/duplikatów widzianych przez sensor.
    """
    seq = get_sequence_number(packet)
    frag = get_fragment_number(packet)

    if seq is None:
        return None

    dot11 = packet.getlayer(Dot11)

    return (
        normalize_mac(getattr(dot11, "addr1", None)),
        normalize_mac(getattr(dot11, "addr2", None)),
        normalize_mac(getattr(dot11, "addr3", None)),
        seq,
        frag,
        int(getattr(dot11, "subtype", -1)),
    )


def prune_queue(events, now):
    while events and now - events[0][0] > WINDOW_SECONDS:
        events.popleft()


def queue_contains_identity(events, identity):
    if identity is None:
        return False

    return any(item[1] == identity for item in events)


def detect_probe_flood(packet):
    if not packet.haslayer(Dot11ProbeReq):
        return

    dot11 = packet.getlayer(Dot11)
    source = normalize_mac(getattr(dot11, "addr2", None))

    if not source:
        return

    ssid = get_ssid(packet)
    if ssid is None:
        ssid = ""

    # Klucz per klient + szukane SSID.
    # Normalny klient często szybko sprawdza wiele różnych zapamiętanych SSID.
    # Flood testowy zwykle powtarza wiele ramek dla tego samego SSID.
    key = (source, ssid)

    now = monotonic()
    events = probe_events[key]
    prune_queue(events, now)

    identity = make_frame_identity(packet)

    # Ta sama logiczna ramka może zostać odebrana wielokrotnie jako retransmisja.
    if queue_contains_identity(events, identity):
        return

    events.append((now, identity))

    count = len(events)

    print(
        f"[PROBE] source={source} "
        f"ssid={ssid if ssid else '<wildcard>'} "
        f"count={count}/{PROBE_THRESHOLD}"
    )

    if count < PROBE_THRESHOLD:
        return

    last_alert = last_probe_alert.get(key, 0)

    if now - last_alert < ALERT_COOLDOWN:
        return

    last_probe_alert[key] = now

    detection_latency_ms = round((now - events[0][0]) * 1000, 2)
    radio = get_radio_info(packet)

    event = create_event(
        "PROBE_FLOOD",
        "medium",
        source_mac=source,
        ssid=ssid,
        frame_count=count,
        threshold=PROBE_THRESHOLD,
        window_seconds=WINDOW_SECONDS,
        rssi=radio["rssi"],
        frequency=radio["frequency"],
        channel=radio["capture_channel"],
        detection_latency_ms=detection_latency_ms,
    )

    emit_event(event)

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("[ALERT] Podejrzenie Probe Flood")
    print(f"Źródło: {source}")
    print(f"SSID: {ssid if ssid else '<wildcard>'}")
    print(f"Unikalne ramki: {count}/{PROBE_THRESHOLD}")
    print(f"Detection latency: {detection_latency_ms} ms")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")


def detect_deauth_flood(packet):
    if not (packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas)):
        return

    dot11 = packet.getlayer(Dot11)

    source = normalize_mac(getattr(dot11, "addr2", None))
    destination = normalize_mac(getattr(dot11, "addr1", None))
    bssid = normalize_mac(getattr(dot11, "addr3", None))

    if not bssid:
        return

    # Liczymy wyłącznie ramki wyglądające na wysłane przez AP/BSSID.
    # Zapobiega to podwójnemu liczeniu par ramek AP->STA i STA->AP
    # generowanych podczas niektórych testów Deauth.
    if source != bssid:
        return

    target = destination or BROADCAST_MAC
    key = (bssid, target)

    now = monotonic()
    events = deauth_events[key]
    prune_queue(events, now)

    identity = make_frame_identity(packet)

    if queue_contains_identity(events, identity):
        return

    events.append((now, identity))

    count = len(events)

    print(
        f"[DEAUTH] bssid={bssid} "
        f"target={target} "
        f"count={count}/{DEAUTH_THRESHOLD}"
    )

    if count < DEAUTH_THRESHOLD:
        return

    last_alert = last_deauth_alert.get(key, 0)

    if now - last_alert < ALERT_COOLDOWN:
        return

    last_deauth_alert[key] = now

    detection_latency_ms = round((now - events[0][0]) * 1000, 2)
    radio = get_radio_info(packet)

    event = create_event(
        "DEAUTH_FLOOD",
        "high",
        bssid=bssid,
        source_mac=source,
        destination_mac=target,
        frame_type=get_frame_type(packet),
        frame_count=count,
        threshold=DEAUTH_THRESHOLD,
        window_seconds=WINDOW_SECONDS,
        rssi=radio["rssi"],
        frequency=radio["frequency"],
        channel=radio["capture_channel"],
        detection_latency_ms=detection_latency_ms,
    )

    emit_event(event)

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("[ALERT] Podejrzenie Deauthentication / Disassociation Flood")
    print(f"BSSID: {bssid}")
    print(f"Cel: {target}")
    print(f"Unikalne ramki AP->cel: {count}/{DEAUTH_THRESHOLD}")
    print(f"Detection latency: {detection_latency_ms} ms")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")


def detect_rogue_ap(packet):
    if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        return

    dot11 = packet.getlayer(Dot11)
    bssid = normalize_mac(getattr(dot11, "addr3", None))

    if not bssid:
        return

    ssid = get_ssid(packet)

    if ssid is None or ssid not in TRUSTED_APS:
        return

    trusted_bssids = {normalize_mac(x) for x in TRUSTED_APS.get(ssid, set())}

    if bssid in trusted_bssids:
        return

    now = monotonic()
    key = (ssid, bssid)

    if now - last_rogue_alert.get(key, 0) < ALERT_COOLDOWN:
        return

    last_rogue_alert[key] = now

    radio = get_radio_info(packet)
    advertised_channel = get_advertised_channel(packet)
    detection_latency_ms = get_immediate_detection_latency_ms(packet)

    event = create_event(
        "ROGUE_AP",
        "high",
        ssid=ssid,
        bssid=bssid,
        trusted_bssids=sorted(trusted_bssids),
        frame_type=get_frame_type(packet),
        advertised_channel=advertised_channel,
        capture_channel=radio["capture_channel"],
        frequency=radio["frequency"],
        rssi=radio["rssi"],
        detection_latency_ms=detection_latency_ms,
    )

    emit_event(event)

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("[ALERT] Podejrzenie Rogue AP / Evil Twin")
    print(f"SSID: {ssid}")
    print(f"Nieznany BSSID: {bssid}")
    print(f"Zaufane BSSID: {', '.join(sorted(trusted_bssids))}")
    print(f"Typ ramki: {get_frame_type(packet)}")

    if detection_latency_ms is not None:
        print(f"Detection latency: {detection_latency_ms} ms")

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")


def detect_mac_identity_anomaly(packet):
    if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        return

    dot11 = packet.getlayer(Dot11)
    bssid = normalize_mac(getattr(dot11, "addr3", None))

    if not bssid:
        return

    trusted_profiles = {
        normalize_mac(mac): profile
        for mac, profile in TRUSTED_AP_PROFILES.items()
    }

    profile = trusted_profiles.get(bssid)

    if profile is None:
        return

    expected_ssid = profile.get("ssid")
    expected_channel = profile.get("channel")

    observed_ssid = get_ssid(packet)
    advertised_channel = get_advertised_channel(packet)

    radio = get_radio_info(packet)
    capture_channel = radio["capture_channel"]

    observed_channel = advertised_channel
    if observed_channel is None:
        observed_channel = capture_channel

    ssid_mismatch = (
        expected_ssid is not None
        and observed_ssid is not None
        and observed_ssid != expected_ssid
    )

    channel_mismatch = (
        expected_channel is not None
        and observed_channel is not None
        and observed_channel != expected_channel
    )

    if not (ssid_mismatch or channel_mismatch):
        return

    now = monotonic()
    key = (
        bssid,
        observed_ssid,
        observed_channel,
    )

    if now - last_mac_alert.get(key, 0) < ALERT_COOLDOWN:
        return

    last_mac_alert[key] = now

    detection_latency_ms = get_immediate_detection_latency_ms(packet)

    event = create_event(
        "MAC_IDENTITY_ANOMALY",
        "high",
        bssid=bssid,
        expected_ssid=expected_ssid,
        observed_ssid=observed_ssid,
        expected_channel=expected_channel,
        observed_channel=observed_channel,
        advertised_channel=advertised_channel,
        capture_channel=capture_channel,
        frame_type=get_frame_type(packet),
        rssi=radio["rssi"],
        frequency=radio["frequency"],
        detection_latency_ms=detection_latency_ms,
    )

    emit_event(event)

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("[ALERT] Anomalia tożsamości AP / możliwy MAC spoofing")
    print(f"BSSID: {bssid}")
    print(f"SSID oczekiwany: {expected_ssid}")
    print(f"SSID obserwowany: {observed_ssid}")
    print(f"Kanał oczekiwany: {expected_channel}")
    print(f"Kanał obserwowany: {observed_channel}")

    if detection_latency_ms is not None:
        print(f"Detection latency: {detection_latency_ms} ms")

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")


def process_packet(packet):
    if not packet.haslayer(Dot11):
        return

    detect_deauth_flood(packet)
    detect_probe_flood(packet)
    detect_rogue_ap(packet)
    detect_mac_identity_anomaly(packet)

