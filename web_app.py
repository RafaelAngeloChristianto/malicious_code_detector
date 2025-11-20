"""Simple Flask web UI for malicious_code_detector

- Upload a single .py file
- Runs the existing `Detector` on the uploaded file
- Returns JSON with file content + findings
- Frontend highlights lines with findings (red) and shows badges

Usage:
    pip install -r requirements.txt
    python web_app.py

Open http://127.0.0.1:5000/ in your browser.
"""
from flask import Flask, request, render_template, jsonify, send_from_directory
import os
from code_detector import Detector

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('file')
    if not f:
        return jsonify({'error': 'no file uploaded'}), 400
    filename = f.filename or 'uploaded.py'
    # sanitize filename (basic)
    filename = os.path.basename(filename)
    save_path = os.path.join(UPLOAD_DIR, filename)
    f.save(save_path)
    # read content
    with open(save_path, 'r', encoding='utf-8', errors='ignore') as fh:
        src = fh.read()
    # Run detector on the single file
    det = Detector(save_path)
    # analyze file directly (avoids printing run summary)
    det._analyze_file(save_path, src)
    findings = det.reports
    return jsonify({'filename': filename, 'content': src, 'findings': findings})

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

if __name__ == '__main__':
    app.run(debug=True)
