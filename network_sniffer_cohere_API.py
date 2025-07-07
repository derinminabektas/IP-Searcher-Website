
"""
NetSentinel + Cohere integration (rate limit aware)
- Local statistical labelling
- Cohere (free API key) opinion (max 10 calls per minute)
"""

import csv
import os
import statistics
import time
from collections import defaultdict

from datetime import datetime, timedelta


import matplotlib
import pandas as pd
from dotenv import load_dotenv
from scapy.all import sniff

# Mac uyumlu çizim motoru
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt

# Anahtarları yükle ve Cohere başlat
load_dotenv()
import cohere


api_key = os.getenv("COHERE_API_KEY")
if not api_key:
    print("⚠️  COHERE_API_KEY bulunamadı! .env dosyası oluşturun ve API anahtarınızı ekleyin.")
    print("   https://console.cohere.com/ adresinden ücretsiz API anahtarı alabilirsiniz.")
    co = None
else:
    co = cohere.Client(api_key)



def cohere_assess_packet(size: int) -> str:
    """
    Cohere API'sinden paketin anormal olup olmadığını öğren.
    Yanıt sadece '0' veya '1' olmalı, gerekiyorsa temizle.
    """

    if co is None:
        return "Cohere-err:NoAPIKey"
    
    try:
        # Dinamik eşik değeri hesapla
        df = pd.read_csv("traffic_log.csv")
        normal_sizes = df[df["Local Label"] == "Normal"]["Packet Size"]
        anomalous_sizes = df[df["Local Label"] == "Anomalous"]["Packet Size"]
        
        if len(normal_sizes) > 0 and len(anomalous_sizes) > 0:
            # Hem normal hem anomalous veri varsa
            normal_max = normal_sizes.max()
            anomalous_min = anomalous_sizes.min()
            threshold = (normal_max + anomalous_min) / 2
        elif len(normal_sizes) > 0:
            # Sadece normal veri varsa, normal paketlerin max'ının 1.5 katını kullan
            threshold = normal_sizes.max() * 1.5
        else:
            # Hiç veri yoksa varsayılan değer
            threshold = 1000
        
        prompt = (
            f"You are an AI security analyst analyzing network traffic. Based on the current data:\n"
            f"- Normal packets: {normal_sizes.min()}-{normal_sizes.max()} bytes\n"
            f"- Anomalous packets: {anomalous_sizes.min()}-{anomalous_sizes.max()} bytes\n"
            f"- Threshold: {threshold:.0f} bytes\n\n"
            f"Given the packet size, respond ONLY with:\n"
            f"0 → Normal (if size < {threshold:.0f})\n"
            f"1 → Anomalous (if size >= {threshold:.0f})\n\n"
            f"Packet Size: {size}"
        )
        response = co.chat(
            message=prompt,
            model="command-light",
            temperature=0,
        )
        first_line = response.text.strip().splitlines()[0].strip()
        cleaned = ''.join(filter(str.isdigit, first_line))  # sadece rakamları al
        return cleaned if cleaned in ["0", "1"] else "Cohere-err:InvalidResponse"
    except Exception as e:
        return f"Cohere-err:{e}"



class NetSentinel:
    def __init__(self, t_threshold=5, p_threshold=10, log_file="traffic_log.csv"):
        self.t_thr = t_threshold
        self.p_thr = p_threshold
        self.log = log_file

        self.p_count = 0
        self.sizes = []
        self.ip_times = defaultdict(list)
        self.alerted = set()

        self.lower = None
        self.upper = None
        self.last_api_reset = None  # İlk API çağrısında set edilecek

        self.api_call_count = 0

    def _sampler(self, pkt):
        if pkt.haslayer("IP") and pkt.haslayer("TCP"):
            self.sizes.append(len(pkt))

    def calc_stats(self):

        sniff(filter="tcp or udp", prn=self._sampler, store=0, count=50)
        mean = statistics.mean(self.sizes)
        
        # Sabit eşik değerleri (daha güvenilir)
        self.lower = 50   # Minimum paket boyutu
        self.upper = 1000 # Anormal paket eşiği
            
        print(f"Mean {mean:.2f} → Normal {self.lower:.2f}–{self.upper:.2f}")
        print(f"📊 Eşik: {self.lower} bytes altı veya {self.upper} bytes üstü = Anomalous")

    def _local_label(self, size: int) -> str:
        if self.lower is None or self.upper is None:
            return "Unknown"
        return "Anomalous" if size < self.lower or size > self.upper else "Normal"

    def _handle(self, pkt):
        if not pkt.haslayer("IP"):
            return
        self.p_count += 1

        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        src, dst = pkt["IP"].src, pkt["IP"].dst
        protocol = None
        sp = dp = None
        # ICMP kontrolü
        if pkt.haslayer("ICMP"):
            protocol = "ICMP"
            sp = dp = "N/A"
        # TCP kontrolü (sadece TCP olarak işaretle)
        elif pkt.haslayer("TCP"):
            sp = pkt["TCP"].sport
            dp = pkt["TCP"].dport
            protocol = "TCP"
        # UDP kontrolü ve port bazlı protokol tespiti
        elif pkt.haslayer("UDP"):
            sp = pkt["UDP"].sport
            dp = pkt["UDP"].dport
            protocol = "UDP"
        else:
            protocol = "Other"
            sp = dp = "N/A"

        size = len(pkt)
        local = self._local_label(size)

        now = time.time()
        self.ip_times[src].append(now)
        self.ip_times[src] = [t for t in self.ip_times[src] if now - t <= self.t_thr]
        if len(self.ip_times[src]) > self.p_thr and src not in self.alerted:
            print(f"⚠️  {src} exceeded {self.p_thr} pkts in {self.t_thr}s")
            self.alerted.add(src)


        # Rate limit kontrolü (API çağrısından önce)
        if self.api_call_count >= 10 and self.last_api_reset is not None:
            since = time.time() - self.last_api_reset
            if since < 60:
                wait_time = 60 - since
                print(f"⏳ API limiti doldu, {wait_time:.1f} sn bekleniyor…")
                time.sleep(wait_time)
            self.last_api_reset = time.time()
            self.api_call_count = 0
        
        # Local Label'ı AI Label olarak kullan (daha güvenilir)
        ai = local
        
        # API çağrısı (sadece log için)
        raw = cohere_assess_packet(size)
        self.api_call_count += 1
        
        # İlk API çağrısında zaman damgasını set et
        if self.last_api_reset is None:
            self.last_api_reset = time.time()
        
        # API hata kontrolü (sadece log için)
        if raw.startswith("Cohere-err:"):
            print(f"⚠️  API Error: {raw}")
        else:
            api_result = {"0": "Normal", "1": "Anomalous"}.get(raw, "Unknown")
            print(f"🤖 API önerisi: {api_result} (Local: {local})")

        print(f"{src}:{sp} -> {dst}:{dp} | Size:{size:<4} | Protocol:{protocol:<6} | Local:{local:<9} | AI:{ai:<12} | Total:{self.p_count}")

        with open(self.log, "a", newline="") as f:
            csv.writer(f).writerow(
                [ts, src, dst, sp, dp, protocol, size, local, ai]

            )

    def analyse(self):
        df = pd.read_csv(self.log)
        print("\n📄 First rows:\n", df.head())
        if df.empty:
            print("⚠️  No data.")
            return

        df["Packet Size"].plot.hist(bins=50, alpha=0.7)
        plt.title("Packet Size Distribution")
        plt.xlabel("Bytes")
        plt.ylabel("Freq")
        plt.grid()
        plt.show()

        print("\n📊 Stats:")
        print("Total:", len(df))
        print(df["Protocol"].value_counts(normalize=True).mul(100).round(2).astype(str) + "%")
        print(df.groupby("Protocol")["Packet Size"].agg(["mean", "min", "max"]).round(2))

    def run(self):
        with open(self.log, "w", newline="") as f:
            csv.writer(f).writerow(
                [
                    "Timestamp",
                    "IP Source",
                    "IP Destination",
                    "Source Port",
                    "Destination Port",
                    "Protocol",
                    "Packet Size",
                    "Local Label",
                    "AI Label",
                ]
            )

        self.calc_stats()
        print("🟢 Listening… Ctrl+C to stop.")
        try:
            sniff(filter="tcp or udp", prn=self._handle, store=0)


        except KeyboardInterrupt:
            print("\n⛔ Stopped. Packets:", self.p_count)

        self.analyse()


if __name__ == "__main__":
    NetSentinel().run()