# sniffer.py
import threading
from scapy.all import sniff
from datetime import datetime
import time
import os

shutdown_signal = threading.Event()
sniffing_active = threading.Event()

def packet_callback(packet):
    with open('temporary_packets.log', 'a') as temp_log:
        temp_log.write(f"{datetime.now()} - {packet.summary()}\n")

def sniff_packets():
    global sniffing_active
    while not shutdown_signal.is_set() and sniffing_active.is_set():
        # Ensure that the file 'temporary_packets.log' exists
        if not os.path.exists('temporary_packets.log'):
            with open('temporary_packets.log', 'w'):
                pass  # Create an empty file

        sniff(timeout=5, prn=packet_callback, store=0)

        with open('temporary_packets.log', 'r') as temp_log:
            logs = temp_log.read()

        if logs:
            with open('final_packets.log', 'a') as final_log:
                final_log.write(logs)

            open('temporary_packets.log', 'w').close()

        print("Scanning phase completed. Logs have been appended to final_packets.log.")

        time.sleep(5)

def start_sniffing():
    global sniffing_active
    sniffing_active.set()
    print("Packet Sniffing turned on.")
    threading.Thread(target=sniff_packets).start()

def stop_sniffing():
    global sniffing_active
    sniffing_active.clear()
    print("Packet Sniffing turned off.")

def is_sniffing_active():
    return sniffing_active.is_set()

# Add YARA integration or other components as needed
