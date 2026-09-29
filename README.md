
# Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

This project is a Python packet sniffer created with Scapy and GitHub Copilot assistance. The tool is designed to capture authorized lab traffic, decode basic network protocols, and redact sensitive information before displaying packet information.

## Setup

Requirements:
- Python 3.10 or newer
- Scapy
- macOS or Linux environment

Install Scapy:

python3 -m pip install scapy

## Ethics and Authorized Use

This packet sniffer is intended only for authorized and educational use. Traffic should only be captured on the user's own machine, loopback interface, or an instructor-provided lab VM/network.

The program uses an interface allowlist to limit live capture to approved interfaces. Sensitive information is redacted before output, including IP addresses, email addresses, authorization information, cookies, passwords, and tokens.

The tool should never be used to capture other people's traffic, bypass operating system permissions, hide activity, or access networks without authorization.


## Run Examples

Run the packet sniffer on the authorized loopback interface:

sudo python3 sniffer.py

Generate authorized local HTTP traffic:

curl "http://127.0.0.1/?test=packet"

Generate an authorized local DNS query:

dig @127.0.0.1 example.com

The sniffer captures up to 25 packets and uses the filter "tcp port 80 or udp port 53".


## AI Use Policy

Use Copilot for:
- Boilerplate code
- CLI parsing
- JSON formatting
- Unit test scaffolds

Do not ask Copilot for:
- Capturing other people's traffic
- Bypassing operating system permissions
- Stealth features, persistence, or hiding activity

Always:
- Add an interface/pcap allowlist
- Include redaction
- Default to pcap mode if capture privileges are missing

