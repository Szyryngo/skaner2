import binascii
from core.ai import classify_packet

def format_packet(packet):
    raw = bytes(packet)
    hex_view = binascii.hexlify(raw).decode("utf-8")
    ascii_view = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw])
    return hex_view, ascii_view

def get_packet_summary(index, packet):
    summary = packet.summary()
    classification = classify_packet(packet)
    color = {
        "normal": "white",
        "scan": "orange",
        "malware": "red",
        "flood": "purple"
    }.get(classification, "gray")
    return {
        "index": index,
        "summary": summary,
        "classification": classification,
        "color": color
    }
