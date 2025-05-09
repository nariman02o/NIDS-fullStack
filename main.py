
from flask import Flask, render_template, jsonify, request
import logging
from src.network_monitor import NetworkMonitor
from src.model_trainer import ModelTrainer
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

network_monitor = NetworkMonitor()
model_trainer = ModelTrainer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/threats')
def get_threats():
    return jsonify(network_monitor.get_recent_threats())

@app.route('/api/stats')
def get_stats():
    return jsonify(network_monitor.get_statistics())

@app.route('/api/metrics')
def get_metrics():
    return jsonify(network_monitor.metrics)

@app.route('/api/model/visualizations')
def get_model_visualizations():
    return jsonify(model_trainer.get_model_metrics())

@app.route('/api/model/retrain', methods=['POST'])
def retrain_model():
    try:
        recent_packets = network_monitor.get_training_data()
        if not recent_packets:
            return jsonify({'status': 'error', 'message': 'No training data available'}), 400
            
        success = model_trainer.train(recent_packets['X'], recent_packets['y'])
        if not success:
            return jsonify({'status': 'error', 'message': 'Model training failed'}), 500
            
        logger.info("Model retrained successfully")
        return jsonify({'status': 'success', 'message': 'Model retrained successfully'})
    except Exception as e:
        logger.error(f"Error during model retraining: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/model/export')
def export_model():
    model_data = model_trainer.export_weights()
    return jsonify(model_data)

@app.route('/api/packets')
def get_packets():
    return jsonify([{
        'protocol': p['protocol'],
        'src': p['src_addr'],
        'dst': p['dst_addr'],
        'length': p['length']
    } for p in network_monitor.captured_packets[-100:]])

if __name__ == '__main__':
    # Start packet capture in background
    capture_thread = threading.Thread(target=network_monitor.start_capture)
    capture_thread.daemon = True
    capture_thread.start()
    
    # Start Flask server
    app.run(host='0.0.0.0', port=5000)
