from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
import re

PACKET_COUNT = 25
ALLOWED_INTERFACES = ["lo", "lo0"]

def mask_ip(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".xxx"
    return ip

def redact_sensitive(text):
    """Redact sensitive information before output."""
    
   
    text = re.sub(
        r'\b[\w.-]+@[\w.-]+\.\w+\b',
        '[REDACTED_EMAIL]',
        text
    )

    
    text = re.sub(
        r'(?i)(Authorization:\s*)[^\r\n]+',
        r'\1[REDACTED]',
        text
    )

    
    text = re.sub(
        r'(?i)(Cookie:\s*)[^\r\n]+',
        r'\1[REDACTED]',
        text
    )

    
    text = re.sub(
        r'(?i)(password|token)=([^&\s]+)',
        r'\1=[REDACTED]',
        text
    )

    return text

def process_packet(packet):
    """Decode and safely display captured packet information."""

    if IP in packet:
        src_ip = mask_ip(packet[IP].src)
        dst_ip = mask_ip(packet[IP].dst)

        print(f"\nIP: {src_ip} -> {dst_ip}")

        if TCP in packet:
            print(
                f"TCP: Source Port {packet[TCP].sport} -> "
                f"Destination Port {packet[TCP].dport}"
            )

        elif UDP in packet:
            print(
                f"UDP: Source Port {packet[UDP].sport} -> "
                f"Destination Port {packet[UDP].dport}"
            )

    # Decode DNS queries
    if DNS in packet and packet[DNS].qd and DNSQR in packet:
        domain = packet[DNSQR].qname.decode(
            errors="ignore"
        ).rstrip(".")
        print(f"DNS Query: {domain}")

    # Decode unencrypted HTTP data
    if TCP in packet and Raw in packet:
        payload = bytes(packet[Raw].load).decode(
            errors="ignore"
        )

        if payload.startswith(
            ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")
        ):
            safe_payload = redact_sensitive(payload)
            request_line = safe_payload.split("\r\n")[0]

            host = "Unknown"
            for line in safe_payload.split("\r\n"):
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            print(f"HTTP Request: {request_line}")
            print(f"HTTP Host: {host}")

      def start_capture(interface="lo0"):
    """Capture authorized traffic from an allowed interface."""

    if interface not in ALLOWED_INTERFACES:
        print("Error: Interface is not on the authorized allowlist.")
        return

    print(f"Starting authorized capture on {interface}...")
    print(f"Capturing {PACKET_COUNT} packets.")

    sniff(
        iface=interface,
        prn=process_packet,
        count=PACKET_COUNT,
        filter="tcp port 80 or udp port 53",
        store=False
    )


if __name__ == "__main__":
    start_capture()
