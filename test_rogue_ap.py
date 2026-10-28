from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt

from sniffer import detect_rogue_ap


packet = (
    RadioTap()
    / Dot11(
        type=0,
        subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2="02:aa:bb:cc:dd:ee",
        addr3="02:aa:bb:cc:dd:ee",
    )
    / Dot11Beacon()
    / Dot11Elt(
        ID="SSID",
        info="NETIASPOT-qCr7"
    )
)

detect_rogue_ap(packet)
