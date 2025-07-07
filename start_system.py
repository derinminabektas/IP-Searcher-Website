
"""
HDB Labs + Web Dashboard Başlatma Scripti
"""

import subprocess
import time
import threading
import os
import signal
import sys

# Global process objeleri
sniffer_proc = None
web_proc = None

def start_sniffer():
    """Network sniffer'ı başlat"""
    global sniffer_proc
    try:
        sniffer_proc = subprocess.Popen(["python", "network_sniffer_cohere_API.py"])
        sniffer_proc.wait()
    except Exception as e:
        print(f"❌ Network sniffer hatası: {e}")

def start_web_app():
    """Web uygulamasını başlat"""
    global web_proc
    
    try:
        web_proc = subprocess.Popen(["python", "app.py"])
        web_proc.wait()
    except Exception as e:
        print(f"❌ Web uygulaması hatası: {e}")

def main():
    
    # CSV dosyasını temizle
    if os.path.exists("traffic_log.csv"):
        os.remove("traffic_log.csv")
        print("🗑️  Eski traffic_log.csv temizlendi.")
    
    # Thread'lerde başlat
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    web_thread = threading.Thread(target=start_web_app, daemon=True)
    
    try:
        # Web uygulamasını başlat
        web_thread.start()
        time.sleep(2)  # Web uygulamasının başlaması için bekle
        
        # Network sniffer'ı başlat
        sniffer_thread.start()
        
        print("✅ Sistemler başlatıldı!")
        print("🌐 Web Dashboard: http://localhost:5000")
        print("📊 Network Sniffer: Çalışıyor...")
        print("=" * 50)
        print("⏹️  Durdurmak için Ctrl+C")
        
        # Ana thread'i canlı tut
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Sistemler durduruluyor...")
        # Alt process'leri sonlandır
        global sniffer_proc, web_proc
        if sniffer_proc and sniffer_proc.poll() is None:
            sniffer_proc.terminate()
            print("Sniffer durduruldu.")
        if web_proc and web_proc.poll() is None:
            web_proc.terminate()
            print("Web app durduruldu.")
        sys.exit(0)

if __name__ == "__main__":
    main() 