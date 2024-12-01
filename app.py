# Import Required Libraries
from flask import Flask,jsonify,render_template,send_from_directory
from flask_cors import CORS
from scapy.all import sniff,IP,TCP,UDP,ICMP
from datetime import datetime
import pickle
import threading
import pandas as pd
import os

app=Flask(__name__)
# Enable Cross Origin Resource Sharing
CORS(app)

# Load the Trained Model and Scaler
with open('models\Trained-Model.pkl','rb') as model_file:
    model=pickle.load(model_file)
with open('models\Scaler.sav','rb') as scaler_file:
    scaler=pickle.load(scaler_file)

# Global Variables
capturing=False
data=[]
port_to_service={
    7: ["echo", 13],
    9: ["discard", 10],
    11: ["systat", 59],
    13: ["daytime", 9],
    20: ["ftp_data", 20],
    21: ["ftp", 19],
    22: ["ssh", 56],
    23: ["telnet", 60],
    25: ["smtp", 54],
    37: ["time", 63],
    42: ["name", 36],
    43: ["whois", 69],
    53: ["DNS", 12],
    57: ["mtp", 35],
    69: ["tftp_u", 25],
    70: ["gopher", 21],
    79: ["finger", 18],
    80: ["http", 24],
    84: ["ctf", 8],
    87: ["link", 16],
    95: ["supdup", 58],
    102: ["iso_tsap", 29],
    105: ["csnet_ns", 7],
    109: ["pop_2", 46],
    110: ["pop_3", 47],
    111: ["sunrpc", 57],
    113: ["auth", 4],
    117: ["uucp_path", 67],
    119: ["nntp", 42],
    123: ["ntp_u", 43],
    137: ["netbios_ns", 38],
    138: ["netbios_dgm", 37],
    139: ["netbios_ssn", 39],
    143: ["imap4", 28],
    179: ["bgp", 5],
    194: ["IRC", 0],
    210: ["Z39_50", 2],
    389: ["ldap", 32],
    443: ["https", 26],
    512: ["exec", 17],
    513: ["login", 34],
    514: ["shell", 53],
    530: ["courier", 6],
    540: ["uucp", 66],
    543: ["klogin", 30],
    544: ["kshell", 31],
    587: ["aol", 25],
    1024: ["sql_net", 55],
    2049: ["efs", 33],
    2784: ["http_2784", 25],
    6000: ["X11", 1],
    8001: ["http_8001", 25]
}

# Helper Functions
def detect_service(port):
    """Detect Service Based on Destination Port Number"""
    return port_to_service.get(port,["other",44])[1]

def make_prediction(packet):
    """Predict if the Packet is Normal or an Anomaly"""
    if packet.haslayer(IP):
        src_bytes=int(len(packet[IP]))       # Length of IP Packet Data
        dst_bytes=int(len(packet[IP].payload)) # Payload Length in Destination
        service_encoded=44             # Default 'other' Encoding for Unknown
        # Identify Service for TCP/UDP; For ICMP use a Fixed Service Code
        if packet.haslayer(TCP):
            service_encoded=detect_service(packet.dport)
            if service_encoded==26:
                service_encoded=24
        elif packet.haslayer(UDP):
            service_encoded=detect_service(packet.dport)
        elif packet.haslayer(ICMP):
            service_encoded=53
        data={"src_bytes":src_bytes,"service":service_encoded,"dst_bytes":dst_bytes}
        df=pd.DataFrame([data],columns=['src_bytes','service','dst_bytes'])
        scaled_data=scaler.transform(df)
        prediction=model.predict(scaled_data)
        return prediction[0]

def packet_handler(packet):
    """Handler to Process Each Sniffed Packet and Store Predictions"""
    global data
    if packet.haslayer(IP):
        print("Sniffing Packets...")
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        protocol=packet.sprintf("%IP.proto%")
        prediction=make_prediction(packet)
        prediction_text="Normal" if prediction==1 else "Anomaly"
        # Append Packet Data To The Global Data List
        data.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "prediction": prediction_text
        })

def start_sniffing():
    global capturing
    capturing=True
    sniff(prn=packet_handler,store=False,stop_filter=lambda x:not capturing)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start',methods=['POST'])
def start_capture():
    """Start Capturing Packets"""
    global data,capturing
    data.clear()  # Clear Previous Data
    capturing=True
    threading.Thread(target=start_sniffing).start()  # Run Sniffing in a Separate Thread
    return jsonify({"status":"started"})

@app.route('/stop',methods=['POST'])
def stop_capture():
    """Stop Capturing Packets"""
    global capturing
    capturing=False
    print("Sniffing Stopped...")
    return jsonify({"status":"stopped","data":data})

# Path where the Excel Files will be Saved Temporarily
REPORTS_DIR="reports"
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

@app.route('/generate-report',methods=['POST'])
def generate_report():
    """Generate an Excel Report and Return the File URL"""
    global data
    if not data:
        return jsonify({"status":"error","message":"No Data to Generate Report..."})
    # Convert the Data into a DataFrame
    df=pd.DataFrame(data)
    # Generate a Filename with the Current Timestamp
    report_filename=f"NAD_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    report_filepath=os.path.join(REPORTS_DIR,report_filename)
    # Write the DataFrame to an Excel file
    df.to_excel(report_filepath,index=False,engine='openpyxl')
    # Return the URL for Downloading the File
    return jsonify({"status":"success","file_url":f"/download/{report_filename}"})


@app.route('/download/<filename>')
def download_report(filename):
    """Serve the Generated Excel Report File"""
    return send_from_directory(REPORTS_DIR,filename)

if __name__=='__main__':
    app.run(debug=True)