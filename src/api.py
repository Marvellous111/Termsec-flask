from flask import Flask, jsonify, request
import time
from .traffic import packets, load_pcap
from .detection import analyze_traffic

def register_routes(app):
  @app.route('/traffic')
  def traffic():
    return jsonify({
      "recent_packets": packets[-10:],
      "status": analyze_traffic()
    })
  
  @app.route('/upload', method=['POST'])
  def upload_pcap():
    if 'file' not in request.files:
      return "No file uploaded", 400
    file = request.files['file']
    file.save("uploaded.pcap")
    load_pcap("uploaded.pcap")
    return "PCAP uploaded and processed!"