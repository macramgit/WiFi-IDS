from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt

from config import PROBE_THRESHOLD
from detectors import detect_probe_flood


SOURCE_MAC = "11:22:33:44:55:66"
SSID = "TEST-PROBE-FLOOD"


def create_probe_request(sequence_number):
    return (
        RadioTap()
        / Dot11(
            type=0,
            subtype=4,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=SOURCE_MAC,
            addr3="ff:ff:ff:ff:ff:ff",
            SC=(sequence_number & 0x0FFF) << 4,
        )
        / Dot11ProbeReq()
        / Dot11Elt(ID="SSID", info=SSID)
    )


for i in range(PROBE_THRESHOLD + 5):
    detect_probe_flood(create_probe_request(i))
