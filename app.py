from flask import Flask, jsonify, render_template
import pandas as pd
import csv

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/data")
def get_data():
    """CSV'den son verileri getir"""
    try:
        df = pd.read_csv("traffic_log.csv")
        if df.empty:
            return jsonify({"error": "No data available"})
        
        # Tüm kayıtları getir (limit yok)
        recent_data = df.to_dict('records')
        
        # İstatistikler
        stats = {
            "total_packets": len(df),
            "normal_count": len(df[df["Local Label"] == "Normal"]),
            "anomalous_count": len(df[df["Local Label"] == "Anomalous"]),
            "mean_size": df["Packet Size"].mean(),
            "std_size": df["Packet Size"].std()
        }

        # Aynı API'den 2 veya daha fazla istek kontrolü
        # API anahtarı: (IP Source, IP Destination, Source Port, Destination Port, Protocol)
        api_counts = {}
        api_rows = {}
        for idx, row in df.iterrows():
            key = (row["IP Source"], row["IP Destination"], row["Source Port"], row["Destination Port"], row["Protocol"])
            if key not in api_counts:
                api_counts[key] = 0
                api_rows[key] = []
            api_counts[key] += 1
            # Sıra numarası: en üst satır 1, en alt satır N olacak şekilde
            api_rows[key].append(len(df) - idx)
        duplicate_apis = []
        for key, count in api_counts.items():
            if count >= 2:
                duplicate_apis.append({
                    "api": key,
                    "rows": api_rows[key]
                })
        
        return jsonify({
            "recent_data": recent_data,
            "stats": stats,
            "duplicate_apis": duplicate_apis
        })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/reset", methods=["POST"])
def reset_data():
    """CSV dosyasını sıfırla"""
    try:
        # CSV dosyasını temizle
        with open("traffic_log.csv", "w", newline="") as f:
            csv.writer(f).writerow([
                "Timestamp",
                "IP Source", 
                "IP Destination",
                "Source Port",
                "Destination Port",
                "Protocol",
                "Packet Size",
                "Local Label",
                "AI Label",
            ])
        
        return jsonify({"success": True, "message": "Live traffic data reset successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
