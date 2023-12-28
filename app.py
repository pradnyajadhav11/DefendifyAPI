from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess

app = Flask(__name__)
CORS(app, resources={r"/malwaredetection": {"origins": "http://0.0.0.0:5000"}})

@app.route('/malwaredetection', methods=['POST'])
def malwaredetection():
    try:
        if request.method == 'POST':
            # Check if the content type is 'text/plain'
            if request.content_type == 'text/plain':
                file_path = request.data.decode('utf-8')
            else:
                file_path = request.json.get('file_path')

            if not file_path:
                return jsonify({"error": "File path not provided"}), 400

            result = subprocess.check_output(['python', 'tool.py', file_path], text=True)

            result_json = jsonify({"result": result.strip()})
            return result_json
        else:
            return jsonify({"error": "Method not allowed"}), 405

    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
