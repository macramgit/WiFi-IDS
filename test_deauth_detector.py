from scapy.all import (
    RadioTap,
    Dot11,
    Dot11Deauth,
)

from detectors import detect_deauth_flood


BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "11:22:33:44:55:66"


def create_packet():
    return (
        RadioTap()
        / Dot11(
            type=0,
            subtype=12,
            addr1=CLIENT,
            addr2=BSSID,
            addr3=BSSID,
        )
        / Dot11Deauth(
            reason=7
        )
    )


for _ in range(10):
    detect_deauth_flood(
        create_packet()
    )
