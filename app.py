from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess

app = Flask(__name__)
CORS(app, resources={r"/malwaredetection": {"origins": "http://0.0.0.0:5000"}})

@app.route('/malwaredetection', methods=['POST'])
def malwaredetection():
    try:
        if request.method == 'POST':
            # Check if a file is provided in the request
            if 'file' not in request.files:
                return jsonify({"error": "No file provided"}), 400

            file = request.files['file']

            # Save the file to a temporary location (you might want to handle this differently)
            file_path = '/tmp/' + file.filename
            file.save(file_path)

            result = subprocess.check_output(['python', 'tool.py', file_path], text=True)

            result_json = jsonify({"result": result.strip()})
            return result_json
        else:
            return jsonify({"error": "Method not allowed"}), 405

    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
