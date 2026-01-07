"""LR and AST Compiler for Detecting Malicious and Vulnerability Detector In Python Language
Web Application Interface

Simple Flask web UI for malicious_code_detector

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
import sys
import ast

# Add Backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'Backend'))

# Import SemanticAnalyzer from phase3_LRparser
from phase3_LRparser import SemanticAnalyzer

# Flask app with static and template folders in Frontend directory
app = Flask(__name__, 
            static_folder=os.path.dirname(__file__),
            static_url_path='/static',
            template_folder=os.path.dirname(__file__))

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
        visitor = SemanticAnalyzer(filename)
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
    # Use PORT environment variable for deployment, default to 5000 for local dev
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
