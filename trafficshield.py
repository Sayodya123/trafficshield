#!/usr/bin/env python3
"""
TrafficShield - Advanced DDoS Protection Library
Single-file version: Botnet detection (Mirai-based), rate limiting, IP blacklisting.
Author: Sayodya Hasaranga
License: MIT
"""

import time
import json
import logging
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
from threading import Lock

# ==============================
# Logging setup
# ==============================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("trafficshield")

# ==============================
# 1. Botnet Detector (Mirai-inspired)
# ==============================
class BotnetDetector:
    """
    Detects Mirai-style botnet activity:
    - IP blacklisting
    - C2 beaconing (periodic communication)
    - Signature-based attack patterns
    """
    def __init__(self):
        # IP -> list of timestamps (last 100)
        self.ip_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.blacklisted_ips: set = set()
        self.lock = Lock()
        
        # Known Mirai attack signatures (simplified)
        self.signatures = {
            'udp_flood': {'protocol': 'UDP', 'min_pkt_size': 512, 'max_pkt_size': 1024},
            'syn_flood': {'protocol': 'TCP', 'flags': ['SYN']},
            'http_flood': {'protocol': 'HTTP', 'beacon_interval': (10, 60)},
        }
    
    def update_blacklist(self, ips: List[str]):
        """Add IPs to permanent blacklist"""
        with self.lock:
            self.blacklisted_ips.update(ips)
            logger.info(f"Blacklist updated: +{len(ips)} IPs")
    
    def analyze(self, ip: str, protocol: str = "TCP", packet_size: int = 0, flags: List[str] = None) -> Tuple[bool, float, str]:
        """
        Returns: (is_malicious, confidence_score, reason)
        confidence: 0.0 - 1.0
        """
        # 1. Blacklist check
        if ip in self.blacklisted_ips:
            return True, 1.0, "blacklisted_ip"
        
        # 2. Beaconing detection (C2 communication)
        now = time.time()
        with self.lock:
            self.ip_history[ip].append(now)
            history = list(self.ip_history[ip])
            
            if len(history) >= 5:
                intervals = [history[i] - history[i-1] for i in range(1, len(history))]
                avg_interval = sum(intervals) / len(intervals)
                # Regular intervals within ±3 seconds
                if all(abs(i - avg_interval) <= 3 for i in intervals):
                    return True, 0.75, "c2_beaconing"
        
        # 3. Signature-based detection (Mirai patterns)
        if protocol == "UDP" and 512 <= packet_size <= 1024:
            return True, 0.6, "udp_flood_signature"
        if protocol == "TCP" and flags and "SYN" in flags and len(flags) == 1:
            # Potential SYN flood
            return True, 0.5, "syn_flood_signature"
        
        return False, 0.0, "normal"
    
    def get_stats(self) -> Dict:
        with self.lock:
            return {
                "total_tracked_ips": len(self.ip_history),
                "blacklisted_count": len(self.blacklisted_ips),
                "active_beacons": sum(1 for h in self.ip_history.values() if len(h) >= 5)
            }

# ==============================
# 2. Adaptive Rate Limiter
# ==============================
class AdaptiveRateLimiter:
    """
    Per-IP rate limiting with dynamic thresholds.
    """
    def __init__(self, default_limit: int = 100, time_window: int = 60):
        self.default_limit = default_limit
        self.time_window = time_window  # seconds
        self.ip_requests: Dict[str, deque] = defaultdict(lambda: deque(maxlen=default_limit*2))
        self.ip_limits: Dict[str, int] = defaultdict(lambda: default_limit)
        self.lock = Lock()
    
    def set_limit(self, ip: str, new_limit: int):
        """Dynamically adjust limit for specific IP"""
        with self.lock:
            self.ip_limits[ip] = new_limit
    
    def is_allowed(self, ip: str) -> Tuple[bool, int]:
        """
        Returns: (allowed, current_limit)
        If not allowed, client should be blocked/throttled.
        """
        now = time.time()
        with self.lock:
            # Clean old entries
            old_requests = self.ip_requests[ip]
            while old_requests and old_requests[0] < now - self.time_window:
                old_requests.popleft()
            
            limit = self.ip_limits[ip]
            if len(old_requests) >= limit:
                return False, limit
            
            old_requests.append(now)
            return True, limit
    
    def reset(self, ip: str = None):
        """Reset rate limit data for an IP or all"""
        with self.lock:
            if ip:
                self.ip_requests.pop(ip, None)
                self.ip_limits.pop(ip, None)
            else:
                self.ip_requests.clear()
                self.ip_limits.clear()

# ==============================
# 3. Mitigation Actions
# ==============================
class MitigationEngine:
    """
    Execute actions: block, log, challenge (CAPTCHA placeholder)
    """
    def __init__(self, blocklist_file: str = "blocked_ips.json"):
        self.blocklist_file = blocklist_file
        self.blocked_ips = set()
        self.load_blocklist()
    
    def load_blocklist(self):
        try:
            with open(self.blocklist_file, 'r') as f:
                data = json.load(f)
                self.blocked_ips = set(data.get("ips", []))
        except FileNotFoundError:
            pass
    
    def save_blocklist(self):
        with open(self.blocklist_file, 'w') as f:
            json.dump({"ips": list(self.blocked_ips)}, f)
    
    def block_ip(self, ip: str, reason: str = ""):
        """Permanently block IP (simulated)"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.save_blocklist()
            logger.warning(f"BLOCKED IP: {ip} | Reason: {reason}")
    
    def log_attack(self, ip: str, attack_type: str, confidence: float):
        logger.info(f"ATTACK DETECTED | IP: {ip} | Type: {attack_type} | Confidence: {confidence:.2f}")
    
    def challenge(self, ip: str) -> str:
        """Return a CAPTCHA challenge (simplified)"""
        # In production, integrate with reCAPTCHA or similar
        challenge_code = f"CHALLENGE-{hash(ip) % 10000}"
        logger.info(f"CHALLENGE issued to {ip}: {challenge_code}")
        return challenge_code
    
    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

# ==============================
# 4. Main TrafficShield Class
# ==============================
class TrafficShield:
    """
    Unified DDoS protection library.
    Usage:
        shield = TrafficShield(rate_limit=50, time_window=60)
        if not shield.protect(client_ip, protocol="TCP"):
            return "Blocked", 403
    """
    def __init__(self, rate_limit: int = 100, time_window: int = 60, enable_detector: bool = True):
        self.rate_limiter = AdaptiveRateLimiter(rate_limit, time_window)
        self.detector = BotnetDetector() if enable_detector else None
        self.mitigation = MitigationEngine()
    
    def protect(self, ip: str, protocol: str = "TCP", packet_size: int = 0, flags: List[str] = None) -> Tuple[bool, str]:
        """
        Main entry point. Returns (allowed, reason)
        allowed = False means request should be rejected.
        """
        # 1. Check if IP already blocked
        if self.mitigation.is_blocked(ip):
            return False, "ip_blocked"
        
        # 2. Botnet detection
        if self.detector:
            is_mal, confidence, reason = self.detector.analyze(ip, protocol, packet_size, flags)
            if is_mal:
                self.mitigation.log_attack(ip, reason, confidence)
                if confidence >= 0.7:
                    self.mitigation.block_ip(ip, reason)
                    return False, f"botnet_detected_{reason}"
                elif confidence >= 0.5:
                    # Issue challenge instead of blocking
                    self.mitigation.challenge(ip)
                    return False, "challenge_required"
        
        # 3. Rate limiting
        allowed, limit = self.rate_limiter.is_allowed(ip)
        if not allowed:
            self.mitigation.log_attack(ip, "rate_limit_exceeded", 0.8)
            # Optionally block after multiple rate limit hits (not implemented here)
            return False, f"rate_limit_exceeded (limit {limit}/min)"
        
        return True, "allowed"
    
    def update_blacklist(self, ips: List[str]):
        if self.detector:
            self.detector.update_blacklist(ips)
    
    def get_stats(self) -> Dict:
        stats = {"rate_limiter": {"default_limit": self.rate_limiter.default_limit}}
        if self.detector:
            stats["detector"] = self.detector.get_stats()
        stats["blocked_ips_count"] = len(self.mitigation.blocked_ips)
        return stats

# ==============================
# 5. Example Usage (Flask integration)
# ==============================
def example_flask_integration():
    """
    Run this function to see a simple Flask app with TrafficShield.
    Install flask first: pip install flask
    """
    from flask import Flask, request, jsonify
    
    app = Flask(__name__)
    shield = TrafficShield(rate_limit=30, time_window=60)
    
    @app.before_request
    def before_request():
        client_ip = request.remote_addr
        allowed, reason = shield.protect(client_ip, protocol=request.method)
        if not allowed:
            return jsonify({"error": "Access denied", "reason": reason}), 429 if "rate_limit" in reason else 403
    
    @app.route('/')
    def home():
        return "Welcome! TrafficShield is protecting this server."
    
    @app.route('/stats')
    def stats():
        return jsonify(shield.get_stats())
    
    app.run(host='0.0.0.0', port=5000, debug=True)

# ==============================
# 6. Command-line interface
# ==============================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="TrafficShield DDoS Protection Library")
    parser.add_argument("--test", action="store_true", help="Run basic test")
    parser.add_argument("--flask", action="store_true", help="Run example Flask server")
    parser.add_argument("--rate", type=int, default=100, help="Rate limit per minute")
    parser.add_argument("--window", type=int, default=60, help="Time window in seconds")
    args = parser.parse_args()
    
    if args.flask:
        try:
            example_flask_integration()
        except ImportError:
            print("Flask not installed. Run: pip install flask")
    elif args.test:
        # Basic test
        shield = TrafficShield(rate_limit=5, time_window=10)
        test_ip = "192.168.1.100"
        print("=== TrafficShield Test ===")
        for i in range(10):
            allowed, reason = shield.protect(test_ip)
            print(f"Request {i+1}: {'ALLOWED' if allowed else 'BLOCKED'} - {reason}")
            time.sleep(0.5)
        
        # Test botnet detection
        print("\n--- Botnet Beaconing Test ---")
        shield2 = TrafficShield(rate_limit=100)
        for _ in range(6):
            allowed, reason = shield2.protect("10.0.0.1", protocol="UDP", packet_size=800)
            print(f"Beacon test: {reason}")
            time.sleep(1)
        print("Stats:", shield2.get_stats())
    else:
        print("TrafficShield Library - Import to use.\nOptions: --test, --flask")
