from scapy.all import *
from scapy.layers.inet import IP


def main():
    ip_option_list = {
        "rr": [IPOption_RR(), "Record route"],
        "lsrr": [IPOption_LSRR(routers=["1.2.3.4", "5.6.7.8"]), "Loose source route"],
        "eol": [IPOption_EOL(), "EOL"],
        "nop": [IPOption_NOP(), "NOP"],
        "ts": [IPOption_Timestamp(flg=0, length=8), "Timestamp"],
        "sec": [IPOption_Security(transmission_control_code="XYZ"), "Security"],
        "ssrr": [IPOption_SSRR(routers=["1.1.1.1", "8.8.8.8"]), "Strict source route"],
        "satid": [IPOption_Stream_Id(), "Stream id"],
    }

    # Create and send a packet for each IP option
    src_ip = "9.10.11.12"
    dst_ip = "13.14.15.16"
    for option in ip_option_list:
        print(f"Creating packet with ip option {option}")
        packet = IP(src=src_ip, dst=dst_ip, options=ip_option_list[option][0]) / TCP()
        wrpcap("input.pcap", packet, append=True)


if __name__ == "__main__":
    main()
