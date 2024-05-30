from scapy.all import *

def modify_packet(packet):
    """
    Function to modify the packet payload.
    :param packet: The original packet
    :return: Modified packet
    """
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        if b'123' in payload:
            modified_payload = payload.replace(b'123', b'456')
            packet[Raw].load = modified_payload
            del packet[IP].len
            del packet[IP].chksum
            del packet[TCP].chksum
            return packet
    return None

def packet_callback(packet):
    modified_packet = modify_packet(packet)
    if modified_packet:
        send(modified_packet)

if __name__ == "__main__":
    # Start sniffing on the network interface
    sniff(iface="eth0", prn=packet_callback, filter="ip host 192.168.60.2 and ip host 192.168.60.1", store=0)
