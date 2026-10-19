
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
from collections import Counter

packet_count = 0
protocol_counts = Counter()


def analyze_packet(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1
    ip_layer = packet[IP]

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    else:
        protocol = "Other IP"

    protocol_counts[protocol] += 1

    print("\n" + "=" * 55)
    print(f"Packet number: {packet_count}")
    print("Time:", datetime.now().strftime("%H:%M:%S"))
    print("Source IP:", ip_layer.src)
    print("Destination IP:", ip_layer.dst)
    print("Protocol:", protocol)
    print("Packet size:", len(packet), "bytes")

    if TCP in packet:
        print("Source port:", packet[TCP].sport)
        print("Destination port:", packet[TCP].dport)
    elif UDP in packet:
        print("Source port:", packet[UDP].sport)
        print("Destination port:", packet[UDP].dport)

    if Raw in packet:
        payload = bytes(packet[Raw].load)
        print("Payload size:", len(payload), "bytes")
        print("Payload preview (hex):", payload[:16].hex())
    else:
        print("No raw payload detected.")


def main():
    print("=" * 55)
    print("       CodeAlpha - Basic Network Sniffer")
    print("=" * 55)
    print("Filter: IPv4 packets")
    print("Press Ctrl+C to stop the capture.\n")

    try:
        sniff(
            filter="ip",
            prn=analyze_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as error:
        print("\nCapture error:", error)
        print("Check permissions and network capture support.")
    finally:
        print("\n" + "=" * 55)
        print("             CAPTURE SUMMARY")
        print("=" * 55)
        print("Total IP packets analyzed:", packet_count)

        if protocol_counts:
            print("\nPackets by protocol:")
            for protocol, count in protocol_counts.most_common():
                print(f"{protocol}: {count}")
        else:
            print("No IP packets were analyzed.")

        print("=" * 55)


if __name__ == "__main__":
    main()

