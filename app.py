from flask import Flask 
from src.traffic import packet_sniffer
import time
from src.api import register_routes

app = Flask(__name__)
register_routes(app)

@app.route('/')
def index():
    return "TermSec is alive!"

@app.route('/start')
def start():
    packet_sniffer()
    return "Sniffing started!"


@app.route('/status')
def status():
    from src.detection import analyze_traffic
    return analyze_traffic()

if __name__ == "__main__":
    app.run(debug=True)