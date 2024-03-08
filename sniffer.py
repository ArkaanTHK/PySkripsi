from scapy.all import sniff
from scapy.utils import PcapWriter
from datetime import datetime
from time import sleep
from os import path
from threading import Event, Thread

class Sniffer:
    def __init__(self, sniffing_active: Event, shutdown_signal: Event):
        self.sniffing_active = sniffing_active
        self.shutdown_signal = shutdown_signal
        self.pkt_dump = PcapWriter('captured_packets.pcap', append=True, sync=True)

    def start_sniffing(self):
        self.sniffing_active.set()
        print("Packet Sniffing turned on.")
        Thread(target=self.sniff_packets).start()

    def stop_sniffing(self):
        self.sniffing_active.clear()
        print("Packet Sniffing turned off.")
    
    def packet_callback(self, packet):
        with open('temporary_packets.log', 'a') as temp_log:
            temp_log.write(f"{datetime.now()} - {packet.summary()}\n")

        self.pkt_dump.write(packet)

    def sniff_packets(self):
        while not self.shutdown_signal.is_set() and self.sniffing_active.is_set():
            if not path.exists('temporary_packets.log'):
                with open('temporary_packets.log', 'w'):
                    pass

            sniff(timeout=5, prn=self.packet_callback, store=0)
            
            with open('temporary_packets.log', 'r') as temp_log:
                logs = temp_log.read()

            if logs:
                with open('final_packets.log', 'a') as final_log:
                    final_log.write(logs)

                open('temporary_packets.log', 'w').close()

            sleep(5)

    def is_sniffing_active(self):
        return self.sniffing_active.is_set()
