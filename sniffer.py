from scapy.all import sniff
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
    INTERFACE,
    WINDOW_SECONDS,
    DEAUTH_THRESHOLD,
    PROBE_THRESHOLD,
)

from detectors import (
    detect_deauth_flood,
    detect_probe_flood,
    detect_rogue_ap,
    detect_mac_identity_anomaly,
)


DEBUG_FRAMES = False


def get_ssid(packet):
    if not packet.haslayer(Dot11):
        return None

    element = packet.getlayer(Dot11Elt)

    while element is not None:
        if element.ID == 0:
            try:
                return element.info.decode("utf-8", errors="ignore")
            except Exception:
                return None

        element = element.payload.getlayer(Dot11Elt)

    return None


def get_channel(packet):
    element = packet.getlayer(Dot11Elt)

    while element is not None:
        if element.ID == 3:
            try:
                return int(element.info[0])
            except Exception:
                return None

        element = element.payload.getlayer(Dot11Elt)

    return None


def get_rssi(packet):
    return getattr(packet, "dBm_AntSignal", None)


def get_frame_type(packet):
    if packet.haslayer(Dot11Deauth):
        return "Deauthentication"

    if packet.haslayer(Dot11Disas):
        return "Disassociation"

    if packet.haslayer(Dot11Beacon):
        return "Beacon"

    if packet.haslayer(Dot11ProbeReq):
        return "Probe Request"

    if packet.haslayer(Dot11ProbeResp):
        return "Probe Response"

    return None


def print_frame(packet):
    if not DEBUG_FRAMES:
        return

    frame_type = get_frame_type(packet)

    if frame_type is None:
        return

    dot11 = packet.getlayer(Dot11)

    src = getattr(dot11, "addr2", None)
    dst = getattr(dot11, "addr1", None)
    bssid = getattr(dot11, "addr3", None)

    ssid = get_ssid(packet)
    channel = get_channel(packet)
    rssi = get_rssi(packet)

    print(
        f"type={frame_type:<24} "
        f"src={src} "
        f"dst={dst} "
        f"bssid={bssid} "
        f"ssid='{ssid}' "
        f"channel={channel} "
        f"rssi={rssi}"
    )


def process_packet(packet):
    if not packet.haslayer(Dot11):
        return

    print_frame(packet)

    if packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas):
        detect_deauth_flood(packet)

    if packet.haslayer(Dot11ProbeReq):
        detect_probe_flood(packet)

    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        detect_rogue_ap(packet)
        detect_mac_identity_anomaly(packet)


def main():
    print(f"Nasłuchiwanie na {INTERFACE}.")
    print(f"Deauth: {DEAUTH_THRESHOLD} ramek / {WINDOW_SECONDS} s")
    print(f"Probe Flood: {PROBE_THRESHOLD} ramek / {WINDOW_SECONDS} s")
    print("Rogue AP: monitorowanie zaufanych SSID/BSSID")
    print("MAC anomaly: monitorowanie profilu zaufanych AP")

    if DEBUG_FRAMES:
        print("Debug ramek: WŁĄCZONY")
    else:
        print("Debug ramek: wyłączony")

    print("Ctrl+C aby zakończyć.")

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        store=False,
    )


if __name__ == "__main__":
    main()
