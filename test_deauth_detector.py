from scapy.all import RadioTap, Dot11, Dot11Deauth

from config import DEAUTH_THRESHOLD
from detectors import detect_deauth_flood


BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "11:22:33:44:55:66"


def create_packet(sequence_number):
    return (
        RadioTap()
        / Dot11(
            type=0,
            subtype=12,
            addr1=CLIENT,
            addr2=BSSID,
            addr3=BSSID,
            SC=(sequence_number & 0x0FFF) << 4,
        )
        / Dot11Deauth(reason=7)
    )


for i in range(DEAUTH_THRESHOLD + 2):
    detect_deauth_flood(create_packet(i))
