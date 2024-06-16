import argparse
from scapy.all import *


# Function for sending the loaded pcap ( Args are the path to the pcap file, the destination ip address, the destination port and if you want to see the payload you are sending )
def send_payloads(pcap_file, ip_dst, port_dst, debug=False):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Loop through the packets
    for packet in packets:
        # I have not tried TCP yet, but it should works too
        if packet.haslayer(UDP):
            # Show the last layer of the packet if debug mode is enabled
            if debug:
                packet.lastlayer().show()

            # Send the payload to the target IP and port over UDP with the sender's native upper layers. It is possible to replace "IP(dst=ip_dst)" with something more interesting like "IP(src='8.8.8.8',dst=ip_dst)"
            send(IP(dst=ip_dst) / UDP(sport=14974, dport=port_dst) / packet.lastlayer())

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Send payloads extracted from a pcap file to a target IP and port. It supports UDP only at this time.")
    parser.add_argument("-p", "--pcap", required=True, help="Path to the pcap file")
    parser.add_argument("-t","--target", required=True, help="Target IP address and port in the format 'IP:port'")
    parser.add_argument("-d","--debug", action="store_true", help="Enable debug mode to show the packet sent")
    args = parser.parse_args()

    # Extract IP and port from --target argument
    try:
        ip_dst, port_dst = args.target.split(":")
        port_dst = int(port_dst)
    except ValueError:
        print("Error: Invalid format for --target argument. Use 'IP:port'.")
        return

    # Call function to send payloads
    send_payloads(args.pcap, ip_dst, port_dst, args.debug)

if __name__ == "__main__":
    main()
