from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt

from sniffer import detect_probe_flood


SOURCE_MAC = "11:22:33:44:55:66"


def create_probe_request():
    return (
        RadioTap()
        / Dot11(
            type=0,
            subtype=4,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=SOURCE_MAC,
            addr3="ff:ff:ff:ff:ff:ff",
        )
        / Dot11ProbeReq()
        / Dot11Elt(ID="SSID", info="")
    )


for _ in range(20):
    packet = create_probe_request()
    detect_probe_flood(packet)
