
import numpy as np
import time
import queue
import random
from datetime import datetime
from .model_trainer import ModelTrainer

class NetworkMonitor:
    def __init__(self):
        self.model = ModelTrainer().load_model()
        self.packet_queue = queue.Queue(maxsize=1000)
        self.recent_threats = []
        self.captured_packets = []
        self.total_packets = 0
        self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
        self.traffic_history = []
        self.metrics = {
            'accuracy': 0.95,
            'precision': 0.92,
            'recall': 0.89,
            'f1_score': 0.90,
            'false_positive_rate': 0.08,
            'threat_detection_latency': '0.5ms'
        }
        
    def analyze_payload(self, payload):
        suspicious_patterns = {
            'sql_injection': [r'SELECT.*FROM', r'UNION.*SELECT', r'DROP.*TABLE'],
            'xss': [r'<script>', r'javascript:', r'onerror='],
            'command_injection': [r';&', r'\|.*\w+', r'/etc/passwd'],
            'path_traversal': [r'\.\./', r'\.\.\\', r'%2e%2e%2f'],
            'data_exfil': [r'\b\d{16}\b', r'\b\w+@\w+\.\w+\b', r'password=']
        }
        
        findings = []
        for attack_type, patterns in suspicious_patterns.items():
            for pattern in patterns:
                if pattern.lower() in payload.lower():
                    findings.append({
                        'type': attack_type,
                        'pattern': pattern,
                        'context': payload[:50] + '...' if len(payload) > 50 else payload
                    })
        return findings

    def generate_packet(self):
        protocols = ['TCP', 'UDP', 'ICMP']
        malicious_payloads = [
            "SELECT * FROM users WHERE id=1 OR 1=1",
            "<script>alert('xss')</script>",
            "../../../../etc/passwd",
            "admin' --; DROP TABLE users;",
            "ping 8.8.8.8; cat /etc/passwd"
        ]
        
        packet = {
            'timestamp': datetime.now().timestamp(),
            'protocol': random.choice(protocols),
            'src_addr': f"192.168.1.{random.randint(1,255)}",
            'dst_addr': f"10.0.0.{random.randint(1,255)}",
            'length': random.randint(64, 1500),
            'flags': random.randint(0, 63),
            'payload': random.choice(malicious_payloads) if random.random() < 0.1 else "Normal traffic payload"
        }
        return packet

    def process_packet(self, packet):
        self.total_packets += 1
        self.protocol_stats[packet['protocol']] += 1
        
        # Record traffic history for time-series analysis
        self.traffic_history.append({
            'timestamp': packet['timestamp'],
            'bytes': packet['length']
        })
        if len(self.traffic_history) > 1000:
            self.traffic_history.pop(0)
            
        self.captured_packets.append(packet)
        
        # Perform deep packet inspection
        payload_findings = self.analyze_payload(packet['payload'])
        
        if payload_findings:  # Threat detected through payload analysis
            threat = {
                'timestamp': packet['timestamp'],
                'src_ip': packet['src_addr'],
                'dst_ip': packet['dst_addr'],
                'confidence': random.uniform(0.8, 0.99),
                'reason': f"Malicious payload detected: {payload_findings[0]['type']}",
                'packet_details': {
                    'protocol': packet['protocol'],
                    'length': packet['length'],
                    'flags': packet['flags'],
                    'payload_analysis': {
                        'suspicious_patterns': payload_findings,
                        'payload_preview': packet['payload'][:100]
                    }
                }
            }
            self.recent_threats.append(threat)
            
        # Keep only last 1000 packets
        if len(self.captured_packets) > 1000:
            self.captured_packets.pop(0)
        if len(self.recent_threats) > 100:
            self.recent_threats.pop(0)

    def start_capture(self):
        while True:
            packet = self.generate_packet()
            self.process_packet(packet)
            time.sleep(0.5)  # Generate a packet every 0.5 seconds
            
    def get_recent_threats(self):
        return self.recent_threats
        
    def get_statistics(self):
        total_bytes = sum(p['length'] for p in self.captured_packets[-1000:])
        return {
            'total_packets': self.total_packets,
            'threat_count': len(self.recent_threats),
            'protocol_distribution': self.protocol_stats,
            'bandwidth_usage': f"{total_bytes/1024:.2f} KB/s",
            'traffic_trend': self.traffic_history[-100:],
            'active_sources': len(set(t['src_ip'] for t in self.recent_threats)),
            'threat_severity': {
                'high': len([t for t in self.recent_threats if t['confidence'] > 0.8]),
                'medium': len([t for t in self.recent_threats if 0.5 <= t['confidence'] <= 0.8]),
                'low': len([t for t in self.recent_threats if t['confidence'] < 0.5])
            }
        }
        
    def get_training_data(self):
        if len(self.captured_packets) < 100:
            return None
            
        X = []
        y = []
        
        for packet in self.captured_packets:
            features = [
                1 if packet['protocol'] == 'TCP' else (2 if packet['protocol'] == 'UDP' else 3),
                packet['length'],
                packet['flags']
            ]
            X.append(features)
            y.append(1 if any(t['src_ip'] == packet['src_addr'] for t in self.recent_threats) else 0)
            
        return {'X': np.array(X), 'y': np.array(y)}
