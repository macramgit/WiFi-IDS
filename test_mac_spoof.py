from scapy.all import (
    RadioTap,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
)

from detectors import detect_mac_identity_anomaly


TRUSTED_BSSID = "64:bf:6b:7f:4d:9c"


packet = (
    RadioTap()
    / Dot11(
        type=0,
        subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=TRUSTED_BSSID,
        addr3=TRUSTED_BSSID,
    )
    / Dot11Beacon()
    / Dot11Elt(
        ID=0,
        info=b"NETIASPOT-qCr7",
    )
    / Dot11Elt(
        ID=3,
        info=bytes([11]),
    )
)


detect_mac_identity_anomaly(packet)
