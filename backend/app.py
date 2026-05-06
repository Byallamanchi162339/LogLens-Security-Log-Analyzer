from flask import Flask, request, jsonify
from log_analyzer import analyze_log

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():
    if "logfile" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["logfile"]
    content = file.read().decode("utf-8", errors="ignore")

    result = analyze_log(content)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
