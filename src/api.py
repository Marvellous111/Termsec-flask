from flask import Flask, flash, jsonify, request, redirect, url_for
from werkzeug.utils import secure_filename
import os
from data.packetdata import packets
from .traffic import load_pcap
from .detection import analyze_traffic


UPLOAD_FOLDER= "/uploadedfiles"
ALLOWED_EXTENSIONS = {'pcap'}


def register_routes(app):
  app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
  @app.route('/traffic')
  def traffic():
    return jsonify({
      "recent_packets": packets[-10:],
      "status": analyze_traffic()
    })
  
  def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
  
  @app.route('/upload', methods=['GET', 'POST'])
  def upload_pcap():
    if request.method == 'POST':
      # We want to check if the post request has the file part
      if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
      file = request.files['file']
      # If the user doesn't select a file the browser submits an empty file without a filename
      if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
      if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('download_file', name=filename))
    return "PCAP UPLOADED AND PROCESSED", 200
        

# if 'file' not in request.files:
#   return "No file uploaded", 400
# file = request.files['file']
# file.save("uploaded.pcap")
# load_pcap("uploaded.pcap")
# return "PCAP uploaded and processed!", 200