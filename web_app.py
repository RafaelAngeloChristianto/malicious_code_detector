"""Simple Flask web UI for malicious_code_detector

- Upload a single .py file
- Runs the existing `Detector` on the uploaded file (in-memory, no disk storage)
- Returns JSON with file content + findings
- Frontend highlights lines with findings (red) and shows badges

Usage:
    pip install -r requirements.txt
    python web_app.py

Open http://127.0.0.1:5000/ in your browser.
"""
from flask import Flask, request, render_template, jsonify
import os
import ast
from code_detector import Detector, CodeVisitor

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
    
    # Read content directly from uploaded file (in-memory, no disk storage)
    src = f.read().decode('utf-8', errors='ignore')
    
    # Analyze the code in-memory
    parse_traces = []
    findings = []
    
    try:
        tree = ast.parse(src, filename=filename)
        visitor = CodeVisitor(filename)
        visitor.visit(tree)
        
        # Get findings and parse traces
        findings = visitor.findings
        if hasattr(visitor, 'grammar_parser') and hasattr(visitor.grammar_parser, 'parse_traces'):
            parse_traces = visitor.grammar_parser.parse_traces
    except SyntaxError as e:
        return jsonify({
            'error': f'Syntax error in uploaded file: {str(e)}',
            'filename': filename
        }), 400
    except Exception as e:
        import traceback
        traceback.print_exc()  # Print full traceback to console
        return jsonify({
            'error': f'Error analyzing file: {str(e)}',
            'filename': filename
        }), 500
    
    return jsonify({
        'filename': filename, 
        'content': src, 
        'findings': findings,
        'parse_traces': parse_traces
    })

if __name__ == '__main__':
    app.run(debug=True)
