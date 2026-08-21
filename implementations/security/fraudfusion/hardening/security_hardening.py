"""
Fraud Fusion Security Hardening Module
Implements comprehensive security hardening for fraud detection platform.

Components:
- Content Security Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- Input Validation Framework
- Encryption at Rest and in Transit
- Secure Session Management
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple, Union
from functools import wraps
import ipaddress
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
logger = logging.getLogger(__name__)


class ValidationResult(Enum):
    """Input validation result"""
    VALID = "valid"
    INVALID = "invalid"
    SANITIZED = "sanitized"
    BLOCKED = "blocked"


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms"""
    AES_256_GCM = "aes-256-gcm"
    AES_256_CBC = "aes-256-cbc"
    CHACHA20_POLY1305 = "chacha20-poly1305"


class SessionState(Enum):
    """Session states"""
    ACTIVE = "active"
    IDLE = "idle"
    EXPIRED = "expired"
    REVOKED = "revoked"
    LOCKED = "locked"


@dataclass
class CSPDirective:
    """Content Security Policy directive"""
    name: str
    values: List[str]

    def to_string(self) -> str:
        return f"{self.name} {' '.join(self.values)}"


@dataclass
class SecurityHeaders:
    """Security headers configuration"""
    csp: List[CSPDirective]
    hsts_max_age: int
    hsts_include_subdomains: bool
    hsts_preload: bool
    x_frame_options: str
    x_content_type_options: str
    x_xss_protection: str
    referrer_policy: str
    permissions_policy: Dict[str, List[str]]

    def to_dict(self) -> Dict[str, str]:
        headers = {}

        # Content-Security-Policy
        csp_value = "; ".join(d.to_string() for d in self.csp)
        headers['Content-Security-Policy'] = csp_value

        # Strict-Transport-Security
        hsts_parts = [f"max-age={self.hsts_max_age}"]
        if self.hsts_include_subdomains:
            hsts_parts.append("includeSubDomains")
        if self.hsts_preload:
            hsts_parts.append("preload")
        headers['Strict-Transport-Security'] = "; ".join(hsts_parts)

        # Other security headers
        headers['X-Frame-Options'] = self.x_frame_options
        headers['X-Content-Type-Options'] = self.x_content_type_options
        headers['X-XSS-Protection'] = self.x_xss_protection
        headers['Referrer-Policy'] = self.referrer_policy

        # Permissions-Policy
        pp_parts = []
        for feature, origins in self.permissions_policy.items():
            if origins:
                pp_parts.append(f"{feature}=({' '.join(origins)})")
            else:
                pp_parts.append(f"{feature}=()")
        headers['Permissions-Policy'] = ", ".join(pp_parts)

        return headers


@dataclass
class ValidationRule:
    """Input validation rule"""
    name: str
    pattern: Optional[Pattern] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    allowed_chars: Optional[str] = None
    blocked_patterns: List[Pattern] = field(default_factory=list)
    custom_validator: Optional[Callable[[str], bool]] = None
    sanitizer: Optional[Callable[[str], str]] = None
    error_message: str = "Invalid input"


@dataclass
class EncryptionKey:
    """Encryption key metadata"""
    key_id: str
    algorithm: EncryptionAlgorithm
    created_at: datetime
    expires_at: Optional[datetime]
    purpose: str
    status: str = "active"
    key_material: bytes = field(default=b"", repr=False)
@dataclass
class SecureSession:
    """Secure session data"""
    session_id: str
    user_id: str
    organization_id: Optional[str]
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    ip_address: str
    user_agent: str
    device_fingerprint: str
    state: SessionState
    mfa_verified: bool
    security_level: int
    attributes: Dict[str, Any] = field(default_factory=dict)
    activity_log: List[Dict[str, Any]] = field(default_factory=list)


class ContentSecurityPolicyManager:
    """
    Content Security Policy (CSP) Manager for Fraud Fusion
    Implements strict CSP to prevent XSS and injection attacks
    """

    def __init__(self):
        self.policies: Dict[str, List[CSPDirective]] = {}
        self.nonce_store: Dict[str, str] = {}
        self._initialize_default_policies()

    def _initialize_default_policies(self):
        """Initialize default CSP policies for Fraud Fusion"""
        # Strict policy for admin/sensitive pages
        self.policies['strict'] = [
            CSPDirective("default-src", ["'self'"]),
            CSPDirective("script-src", ["'self'", "'strict-dynamic'"]),
            CSPDirective("style-src", ["'self'", "'unsafe-inline'"]),
            CSPDirective("img-src", ["'self'", "data:", "https:"]),
            CSPDirective("font-src", ["'self'", "https://fonts.gstatic.com"]),
            CSPDirective("connect-src", ["'self'", "https://api.fraudfusion.com"]),
            CSPDirective("frame-ancestors", ["'none'"]),
            CSPDirective("form-action", ["'self'"]),
            CSPDirective("base-uri", ["'self'"]),
            CSPDirective("object-src", ["'none'"]),
            CSPDirective("upgrade-insecure-requests", []),
            CSPDirective("block-all-mixed-content", []),
        ]

        # Standard policy for regular pages
        self.policies['standard'] = [
            CSPDirective("default-src", ["'self'"]),
            CSPDirective("script-src", ["'self'", "https://cdn.fraudfusion.com"]),
            CSPDirective("style-src", ["'self'", "'unsafe-inline'", "https://cdn.fraudfusion.com"]),
            CSPDirective("img-src", ["'self'", "data:", "https:", "blob:"]),
            CSPDirective("font-src", ["'self'", "https://fonts.gstatic.com", "https://cdn.fraudfusion.com"]),
            CSPDirective("connect-src", ["'self'", "https://api.fraudfusion.com", "wss://ws.fraudfusion.com"]),
            CSPDirective("frame-ancestors", ["'self'"]),
            CSPDirective("form-action", ["'self'"]),
            CSPDirective("base-uri", ["'self'"]),
            CSPDirective("object-src", ["'none'"]),
        ]

        # Report-only policy for testing
        self.policies['report-only'] = [
            CSPDirective("default-src", ["'self'"]),
            CSPDirective("report-uri", ["/api/v1/security/csp-report"]),
        ]

        # API policy
        self.policies['api'] = [
            CSPDirective("default-src", ["'none'"]),
            CSPDirective("frame-ancestors", ["'none'"]),
        ]

    def generate_nonce(self, request_id: str) -> str:
        """Generate CSP nonce for inline scripts"""
        nonce = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
        self.nonce_store[request_id] = nonce
        return nonce

    def get_policy(
        self,
        policy_name: str,
        nonce: Optional[str] = None,
        additional_sources: Optional[Dict[str, List[str]]] = None
    ) -> str:
        """Get CSP policy string"""
        directives = self.policies.get(policy_name, self.policies['standard']).copy()

        # Add nonce to script-src if provided
        if nonce:
            for directive in directives:
                if directive.name == 'script-src':
                    directive.values.append(f"'nonce-{nonce}'")
                    break

        # Add additional sources
        if additional_sources:
            for directive in directives:
                if directive.name in additional_sources:
                    directive.values.extend(additional_sources[directive.name])

        return "; ".join(d.to_string() for d in directives)

    def validate_csp_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and process CSP violation report"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'document_uri': report.get('document-uri', ''),
            'violated_directive': report.get('violated-directive', ''),
            'blocked_uri': report.get('blocked-uri', ''),
            'source_file': report.get('source-file', ''),
            'line_number': report.get('line-number', 0),
            'column_number': report.get('column-number', 0),
            'severity': self._assess_violation_severity(report),
        }

    def _assess_violation_severity(self, report: Dict[str, Any]) -> str:
        """Assess severity of CSP violation"""
        violated = report.get('violated-directive', '')
        blocked = report.get('blocked-uri', '')

        if 'script-src' in violated:
            return 'high'
        elif 'connect-src' in violated:
            return 'high'
        elif 'frame-ancestors' in violated:
            return 'medium'
        elif 'inline' in blocked:
            return 'medium'
        else:
            return 'low'


class HSTSManager:
    """
    HTTP Strict Transport Security (HSTS) Manager for Fraud Fusion
    Enforces HTTPS connections
    """

    def __init__(self):
        self.config = {
            'max_age': 31536000,  # 1 year
            'include_subdomains': True,
            'preload': True,
        }
        self.preload_domains: Set[str] = set()

    def get_header(self, include_preload: bool = True) -> str:
        """Get HSTS header value"""
        parts = [f"max-age={self.config['max_age']}"]

        if self.config['include_subdomains']:
            parts.append("includeSubDomains")

        if include_preload and self.config['preload']:
            parts.append("preload")

        return "; ".join(parts)

    def validate_https_redirect(self, request_url: str) -> Tuple[bool, str]:
        """Validate HTTPS redirect requirements"""
        if request_url.startswith('https://'):
            return True, "Already HTTPS"

        # Generate HTTPS URL
        https_url = request_url.replace('http://', 'https://', 1)
        return False, https_url

    def check_certificate_transparency(self, domain: str) -> Dict[str, Any]:
        """Check Certificate Transparency requirements"""
        return {
            'domain': domain,
            'ct_required': True,
            'expect_ct_header': f'max-age=86400, enforce, report-uri="https://fraudfusion.com/ct-report"',
        }


class InputValidationFramework:
    """
    Input Validation Framework for Fraud Fusion
    Comprehensive input validation and sanitization
    """

    def __init__(self):
        self.rules: Dict[str, ValidationRule] = {}
        self.blocked_patterns: List[Pattern] = []
        self._initialize_default_rules()
        self._initialize_blocked_patterns()

    def _initialize_default_rules(self):
        """Initialize default validation rules for Fraud Fusion"""
        # Email validation
        self.rules['email'] = ValidationRule(
            name='email',
            pattern=re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            max_length=254,
            error_message="Invalid email format",
        )

        # Phone number (Nigerian format)
        self.rules['phone_ng'] = ValidationRule(
            name='phone_ng',
            pattern=re.compile(r'^(\+234|0)[789][01]\d{8}$'),
            error_message="Invalid Nigerian phone number",
        )

        # BVN (Bank Verification Number)
        self.rules['bvn'] = ValidationRule(
            name='bvn',
            pattern=re.compile(r'^\d{11}$'),
            error_message="Invalid BVN format",
        )

        # NIN (National Identification Number)
        self.rules['nin'] = ValidationRule(
            name='nin',
            pattern=re.compile(r'^\d{11}$'),
            error_message="Invalid NIN format",
        )

        # CAC Registration Number
        self.rules['cac_number'] = ValidationRule(
            name='cac_number',
            pattern=re.compile(r'^(RC|BN|IT|LP)?\d{5,7}$', re.IGNORECASE),
            error_message="Invalid CAC registration number",
        )

        # UUID
        self.rules['uuid'] = ValidationRule(
            name='uuid',
            pattern=re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE),
            error_message="Invalid UUID format",
        )

        # API Key
        self.rules['api_key'] = ValidationRule(
            name='api_key',
            pattern=re.compile(r'^ff_[a-zA-Z0-9]{32,64}$'),
            error_message="Invalid API key format",
        )

        # Amount (currency)
        self.rules['amount'] = ValidationRule(
            name='amount',
            pattern=re.compile(r'^\d+(\.\d{1,2})?$'),
            custom_validator=lambda x: 0 < float(x) <= 1000000000,
            error_message="Invalid amount",
        )

        # Document ID
        self.rules['document_id'] = ValidationRule(
            name='document_id',
            pattern=re.compile(r'^[A-Z0-9]{6,20}$'),
            error_message="Invalid document ID",
        )

        # Username
        self.rules['username'] = ValidationRule(
            name='username',
            pattern=re.compile(r'^[a-zA-Z][a-zA-Z0-9._-]{2,29}$'),
            min_length=3,
            max_length=30,
            error_message="Invalid username format",
        )

        # Password
        self.rules['password'] = ValidationRule(
            name='password',
            min_length=14,
            max_length=128,
            custom_validator=self._validate_password_strength,
            error_message="Password does not meet security requirements",
        )

        # Generic text (sanitized)
        self.rules['text'] = ValidationRule(
            name='text',
            max_length=10000,
            sanitizer=self._sanitize_text,
            error_message="Invalid text input",
        )

        # JSON
        self.rules['json'] = ValidationRule(
            name='json',
            max_length=1000000,
            custom_validator=self._validate_json,
            error_message="Invalid JSON format",
        )

        # IP Address
        self.rules['ip_address'] = ValidationRule(
            name='ip_address',
            custom_validator=self._validate_ip_address,
            error_message="Invalid IP address",
        )

        # URL
        self.rules['url'] = ValidationRule(
            name='url',
            pattern=re.compile(r'^https?://[^\s<>"{}|\\^`\[\]]+$'),
            max_length=2048,
            error_message="Invalid URL format",
        )

    def _initialize_blocked_patterns(self):
        """Initialize blocked patterns for security"""
        self.blocked_patterns = [
            # SQL Injection patterns
            re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b)", re.IGNORECASE),
            re.compile(r"(--|;|/\*|\*/|@@|@)", re.IGNORECASE),
            re.compile(r"(\bOR\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
            re.compile(r"(\bAND\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),

            # XSS patterns
            re.compile(r"<script[^>]*>", re.IGNORECASE),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"on\w+\s*=", re.IGNORECASE),
            re.compile(r"<iframe[^>]*>", re.IGNORECASE),
            re.compile(r"<object[^>]*>", re.IGNORECASE),
            re.compile(r"<embed[^>]*>", re.IGNORECASE),

            # Path traversal
            re.compile(r"\.\./", re.IGNORECASE),
            re.compile(r"\.\.\\", re.IGNORECASE),

            # Command injection
            re.compile(r"[;&|`$]", re.IGNORECASE),
            re.compile(r"\$\(", re.IGNORECASE),
            re.compile(r"\$\{", re.IGNORECASE),

            # LDAP injection
            re.compile(r"[)(|*\\]", re.IGNORECASE),
        ]

    def _validate_password_strength(self, password: str) -> bool:
        """Validate password strength"""
        if len(password) < 14:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        # Check for common patterns
        common_patterns = ['password', '123456', 'qwerty', 'admin']
        if any(p in password.lower() for p in common_patterns):
            return False
        return True

    def _sanitize_text(self, text: str) -> str:
        """Sanitize text input"""
        # HTML entity encoding
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        text = text.replace('/', '&#x2F;')
        return text

    def _validate_json(self, value: str) -> bool:
        """Validate JSON string"""
        try:
            json.loads(value)
            return True
        except json.JSONDecodeError:
            return False

    def _validate_ip_address(self, value: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def validate(
        self,
        value: str,
        rule_name: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[ValidationResult, str, Optional[str]]:
        """
        Validate input against rule
        Returns (result, sanitized_value, error_message)
        """
        rule = self.rules.get(rule_name)
        if not rule:
            return ValidationResult.INVALID, value, f"Unknown validation rule: {rule_name}"

        # Check for blocked patterns first
        for pattern in self.blocked_patterns:
            if pattern.search(value):
                logger.warning(f"Blocked pattern detected in input: {rule_name}")
                return ValidationResult.BLOCKED, "", "Input contains blocked content"

        # Length validation
        if rule.min_length and len(value) < rule.min_length:
            return ValidationResult.INVALID, value, f"Input too short (min: {rule.min_length})"

        if rule.max_length and len(value) > rule.max_length:
            return ValidationResult.INVALID, value, f"Input too long (max: {rule.max_length})"

        # Pattern validation
        if rule.pattern and not rule.pattern.match(value):
            return ValidationResult.INVALID, value, rule.error_message

        # Custom validator
        if rule.custom_validator and not rule.custom_validator(value):
            return ValidationResult.INVALID, value, rule.error_message

        # Sanitization
        sanitized = value
        if rule.sanitizer:
            sanitized = rule.sanitizer(value)
            if sanitized != value:
                return ValidationResult.SANITIZED, sanitized, None

        return ValidationResult.VALID, sanitized, None

    def validate_batch(
        self,
        inputs: Dict[str, Tuple[str, str]]
    ) -> Dict[str, Tuple[ValidationResult, str, Optional[str]]]:
        """
        Validate multiple inputs
        inputs: {field_name: (value, rule_name)}
        """
        results = {}
        for field_name, (value, rule_name) in inputs.items():
            results[field_name] = self.validate(value, rule_name)
        return results

    def add_rule(self, rule: ValidationRule):
        """Add custom validation rule"""
        self.rules[rule.name] = rule


class EncryptionManager:
    """
    Encryption Manager for Fraud Fusion
    Handles encryption at rest and in transit
    """

    def __init__(self):
        self.keys: Dict[str, EncryptionKey] = {}
        self.keys_by_id: Dict[str, EncryptionKey] = {}
        self.key_rotation_days = 90
        self.key_version = os.getenv("FRAUDFUSION_ENCRYPTION_KEY_VERSION", "v1").strip()
        if not self.key_version:
            raise ValueError("FRAUDFUSION_ENCRYPTION_KEY_VERSION must not be empty")
        self._master_key = self._load_master_key()
        self._initialize_default_keys()

    def _load_master_key(self) -> bytes:
        """Load the 256-bit deployment secret managed outside process memory."""
        encoded = os.getenv("FRAUDFUSION_ENCRYPTION_MASTER_KEY", "").strip()
        if not encoded:
            raise ValueError("FRAUDFUSION_ENCRYPTION_MASTER_KEY must be configured")
        try:
            material = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except Exception as error:
            raise ValueError("FRAUDFUSION_ENCRYPTION_MASTER_KEY must be URL-safe base64") from error
        if len(material) != 32:
            raise ValueError("FRAUDFUSION_ENCRYPTION_MASTER_KEY must decode to exactly 32 bytes")
        return material

    def _derive_key(self, purpose: str) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"fraudfusion:{purpose}:{self.key_version}".encode("utf-8"),
        ).derive(self._master_key)

    def _initialize_default_keys(self):
        """Initialize deterministic per-purpose keys derived from the deployment secret."""
        key_purposes = [
            ('data_at_rest', EncryptionAlgorithm.AES_256_GCM),
            ('pii_encryption', EncryptionAlgorithm.AES_256_GCM),
            ('session_encryption', EncryptionAlgorithm.CHACHA20_POLY1305),
            ('api_key_encryption', EncryptionAlgorithm.AES_256_GCM),
            ('document_encryption', EncryptionAlgorithm.AES_256_GCM),
        ]
        for purpose, algorithm in key_purposes:
            key = EncryptionKey(
                key_id=f"ff-key-{purpose}-{self.key_version}",
                algorithm=algorithm,
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(days=self.key_rotation_days),
                purpose=purpose,
                key_material=self._derive_key(purpose),
            )
            self.keys[purpose] = key
            self.keys_by_id[key.key_id] = key

    def encrypt(
        self,
        plaintext: bytes,
        purpose: str,
        associated_data: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Encrypt data
        Returns encrypted data with metadata
        """
        key = self.keys.get(purpose)
        if not key:
            raise ValueError(f"No encryption key for purpose: {purpose}")

        # Generate IV/nonce
        iv = secrets.token_bytes(12)  # 96 bits for GCM

        # In production, use actual encryption library (cryptography, pynacl)
        # This is a placeholder showing the structure
        encrypted_data = self._perform_encryption(plaintext, key, iv, associated_data)

        return {
            'key_id': key.key_id,
            'algorithm': key.algorithm.value,
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(encrypted_data['ciphertext']).decode('utf-8'),
            'tag': base64.b64encode(encrypted_data['tag']).decode('utf-8'),
            'encrypted_at': datetime.utcnow().isoformat(),
        }

    def decrypt(
        self,
        encrypted_data: Dict[str, Any],
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """Decrypt data"""
        key_id = encrypted_data.get('key_id')

        key = self.keys_by_id.get(key_id)
        if not key:
            raise ValueError(f"Encryption key not found: {key_id}")

        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])

        # In production, use actual decryption
        return self._perform_decryption(ciphertext, key, iv, tag, associated_data)

    def _perform_encryption(
        self,
        plaintext: bytes,
        key: EncryptionKey,
        iv: bytes,
        associated_data: Optional[bytes]
    ) -> Dict[str, bytes]:
        """Encrypt with an AEAD primitive and split the authentication tag from ciphertext."""
        aad = associated_data or b""
        if key.algorithm == EncryptionAlgorithm.AES_256_GCM:
            encrypted = AESGCM(key.key_material).encrypt(iv, plaintext, aad)
        elif key.algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            encrypted = ChaCha20Poly1305(key.key_material).encrypt(iv, plaintext, aad)
        else:
            raise ValueError(f"Unsupported authenticated encryption algorithm: {key.algorithm.value}")
        return {'ciphertext': encrypted[:-16], 'tag': encrypted[-16:]}

    def _perform_decryption(
        self,
        ciphertext: bytes,
        key: EncryptionKey,
        iv: bytes,
        tag: bytes,
        associated_data: Optional[bytes]
    ) -> bytes:
        """Verify integrity and decrypt with the configured AEAD primitive."""
        aad = associated_data or b""
        payload = ciphertext + tag
        try:
            if key.algorithm == EncryptionAlgorithm.AES_256_GCM:
                return AESGCM(key.key_material).decrypt(iv, payload, aad)
            if key.algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
                return ChaCha20Poly1305(key.key_material).decrypt(iv, payload, aad)
        except Exception as error:
            raise ValueError("ciphertext authentication failed") from error
        raise ValueError(f"Unsupported authenticated encryption algorithm: {key.algorithm.value}")

    def rotate_key(self, purpose: str) -> EncryptionKey:
        """Reject unsafe in-process rotation that would make existing ciphertext unrecoverable."""
        if purpose not in self.keys:
            raise ValueError(f"No encryption key for purpose: {purpose}")
        raise RuntimeError(
            "Rotate encryption through the external secret manager using a new key version and a data migration"
        )

    def get_keys_due_for_rotation(self) -> List[EncryptionKey]:
        """Get keys that need rotation"""
        return [
            k for k in self.keys.values()
            if k.expires_at and k.expires_at <= datetime.utcnow() + timedelta(days=7)
        ]

    def hash_sensitive_data(self, data: str, salt: Optional[str] = None) -> str:
        """Hash sensitive data (e.g., for comparison)"""
        if not salt:
            salt = secrets.token_hex(16)

        # Use PBKDF2 for password-like data
        hash_value = hashlib.pbkdf2_hmac(
            'sha256',
            data.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )

        return f"{salt}${base64.b64encode(hash_value).decode('utf-8')}"

    def verify_hash(self, data: str, hash_string: str) -> bool:
        """Verify hashed data"""
        try:
            salt, stored_hash = hash_string.split('$')
            computed = self.hash_sensitive_data(data, salt)
            return hmac.compare_digest(computed, hash_string)
        except Exception:
            return False


class SecureSessionManager:
    """
    Secure Session Manager for Fraud Fusion
    Implements secure session management
    """

    def __init__(self, encryption_manager: EncryptionManager):
        self.encryption_manager = encryption_manager
        self.sessions: Dict[str, SecureSession] = {}
        self.session_config = {
            'max_duration_hours': 8,
            'idle_timeout_minutes': 15,
            'max_concurrent_sessions': 3,
            'require_secure_cookie': True,
            'cookie_same_site': 'Strict',
            'regenerate_id_interval_minutes': 30,
        }
        self.user_sessions: Dict[str, List[str]] = {}  # user_id -> [session_ids]

    def create_session(
        self,
        user_id: str,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str,
        organization_id: Optional[str] = None,
        mfa_verified: bool = False,
        security_level: int = 1
    ) -> SecureSession:
        """Create new secure session"""
        # Check concurrent session limit
        self._enforce_session_limit(user_id)

        session_id = self._generate_session_id()
        now = datetime.utcnow()

        session = SecureSession(
            session_id=session_id,
            user_id=user_id,
            organization_id=organization_id,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(hours=self.session_config['max_duration_hours']),
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            state=SessionState.ACTIVE,
            mfa_verified=mfa_verified,
            security_level=security_level,
        )

        session.activity_log.append({
            'timestamp': now.isoformat(),
            'action': 'session_created',
            'ip_address': ip_address,
        })

        self.sessions[session_id] = session

        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = []
        self.user_sessions[user_id].append(session_id)

        logger.info(f"Session created: {session_id} for user: {user_id}")

        return session

    def _generate_session_id(self) -> str:
        """Generate cryptographically secure session ID"""
        return f"ff_sess_{secrets.token_urlsafe(32)}"

    def _enforce_session_limit(self, user_id: str):
        """Enforce concurrent session limit"""
        if user_id not in self.user_sessions:
            return

        active_sessions = [
            sid for sid in self.user_sessions[user_id]
            if sid in self.sessions and self.sessions[sid].state == SessionState.ACTIVE
        ]

        max_sessions = self.session_config['max_concurrent_sessions']

        if len(active_sessions) >= max_sessions:
            # Revoke oldest session
            oldest_sid = active_sessions[0]
            self.revoke_session(oldest_sid, "max_sessions_exceeded")

    def validate_session(
        self,
        session_id: str,
        ip_address: str,
        user_agent: str
    ) -> Tuple[bool, Optional[SecureSession], str]:
        """
        Validate session
        Returns (is_valid, session, reason)
        """
        session = self.sessions.get(session_id)

        if not session:
            return False, None, "Session not found"

        # Check state
        if session.state != SessionState.ACTIVE:
            return False, session, f"Session is {session.state.value}"

        # Check expiration
        if datetime.utcnow() >= session.expires_at:
            session.state = SessionState.EXPIRED
            return False, session, "Session expired"

        # Check idle timeout
        idle_timeout = timedelta(minutes=self.session_config['idle_timeout_minutes'])
        if datetime.utcnow() - session.last_activity > idle_timeout:
            session.state = SessionState.IDLE
            return False, session, "Session idle timeout"

        # Validate IP (optional - can be disabled for mobile users)
        if session.ip_address != ip_address:
            session.activity_log.append({
                'timestamp': datetime.utcnow().isoformat(),
                'action': 'ip_change_detected',
                'old_ip': session.ip_address,
                'new_ip': ip_address,
            })
            # Don't invalidate, but log for monitoring

        # Update last activity
        session.last_activity = datetime.utcnow()

        return True, session, "Session valid"

    def revoke_session(self, session_id: str, reason: str = "manual_revocation"):
        """Revoke session"""
        session = self.sessions.get(session_id)
        if session:
            session.state = SessionState.REVOKED
            session.activity_log.append({
                'timestamp': datetime.utcnow().isoformat(),
                'action': 'session_revoked',
                'reason': reason,
            })
            logger.info(f"Session revoked: {session_id}, reason: {reason}")

    def revoke_all_user_sessions(self, user_id: str, reason: str = "security_action"):
        """Revoke all sessions for a user"""
        if user_id in self.user_sessions:
            for session_id in self.user_sessions[user_id]:
                self.revoke_session(session_id, reason)

    def regenerate_session_id(self, old_session_id: str) -> Optional[str]:
        """Regenerate session ID (for security)"""
        session = self.sessions.get(old_session_id)
        if not session or session.state != SessionState.ACTIVE:
            return None

        new_session_id = self._generate_session_id()

        # Update session
        session.session_id = new_session_id
        session.activity_log.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'session_id_regenerated',
            'old_id': old_session_id[:20] + '...',
        })

        # Update storage
        del self.sessions[old_session_id]
        self.sessions[new_session_id] = session

        # Update user sessions
        if session.user_id in self.user_sessions:
            self.user_sessions[session.user_id] = [
                new_session_id if sid == old_session_id else sid
                for sid in self.user_sessions[session.user_id]
            ]

        return new_session_id

    def upgrade_session_security(
        self,
        session_id: str,
        mfa_verified: bool = True,
        new_security_level: int = 2
    ) -> Optional[SecureSession]:
        """Upgrade session security level (after MFA)"""
        session = self.sessions.get(session_id)
        if not session:
            return None

        session.mfa_verified = mfa_verified
        session.security_level = new_security_level
        session.activity_log.append({
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'security_upgraded',
            'mfa_verified': mfa_verified,
            'security_level': new_security_level,
        })

        return session

    def get_session_cookie_options(self) -> Dict[str, Any]:
        """Get secure cookie options"""
        return {
            'httponly': True,
            'secure': self.session_config['require_secure_cookie'],
            'samesite': self.session_config['cookie_same_site'],
            'path': '/',
            'max_age': self.session_config['max_duration_hours'] * 3600,
        }

    def get_active_sessions_for_user(self, user_id: str) -> List[SecureSession]:
        """Get all active sessions for a user"""
        if user_id not in self.user_sessions:
            return []

        return [
            self.sessions[sid]
            for sid in self.user_sessions[user_id]
            if sid in self.sessions and self.sessions[sid].state == SessionState.ACTIVE
        ]

    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        now = datetime.utcnow()
        expired_ids = [
            sid for sid, session in self.sessions.items()
            if session.expires_at < now or session.state in [SessionState.EXPIRED, SessionState.REVOKED]
        ]

        for sid in expired_ids:
            session = self.sessions[sid]
            if session.user_id in self.user_sessions:
                self.user_sessions[session.user_id] = [
                    s for s in self.user_sessions[session.user_id] if s != sid
                ]
            del self.sessions[sid]

        logger.info(f"Cleaned up {len(expired_ids)} expired sessions")


class SecurityHeadersManager:
    """
    Security Headers Manager for Fraud Fusion
    Manages all security-related HTTP headers
    """

    def __init__(self):
        self.csp_manager = ContentSecurityPolicyManager()
        self.hsts_manager = HSTSManager()

    def get_security_headers(
        self,
        page_type: str = 'standard',
        nonce: Optional[str] = None
    ) -> Dict[str, str]:
        """Get all security headers for response"""
        headers = {}

        # Content-Security-Policy
        csp_policy = 'strict' if page_type in ['admin', 'sensitive'] else 'standard'
        headers['Content-Security-Policy'] = self.csp_manager.get_policy(csp_policy, nonce)

        # Strict-Transport-Security
        headers['Strict-Transport-Security'] = self.hsts_manager.get_header()

        # X-Frame-Options
        headers['X-Frame-Options'] = 'DENY' if page_type in ['admin', 'sensitive'] else 'SAMEORIGIN'

        # X-Content-Type-Options
        headers['X-Content-Type-Options'] = 'nosniff'

        # X-XSS-Protection (legacy, but still useful)
        headers['X-XSS-Protection'] = '1; mode=block'

        # Referrer-Policy
        headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions-Policy
        headers['Permissions-Policy'] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )

        # Cache-Control for sensitive pages
        if page_type in ['admin', 'sensitive']:
            headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            headers['Pragma'] = 'no-cache'
            headers['Expires'] = '0'

        # Cross-Origin headers
        headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        headers['Cross-Origin-Embedder-Policy'] = 'require-corp'

        return headers

    def get_api_headers(self) -> Dict[str, str]:
        """Get security headers for API responses"""
        return {
            'Content-Security-Policy': self.csp_manager.get_policy('api'),
            'Strict-Transport-Security': self.hsts_manager.get_header(),
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Cache-Control': 'no-store',
            'Content-Type': 'application/json; charset=utf-8',
        }


class FraudFusionSecurityHardening:
    """
    Main Security Hardening Engine for Fraud Fusion
    Orchestrates all security hardening components
    """

    def __init__(self):
        self.csp_manager = ContentSecurityPolicyManager()
        self.hsts_manager = HSTSManager()
        self.input_validator = InputValidationFramework()
        self.encryption_manager = EncryptionManager()
        self.session_manager = SecureSessionManager(self.encryption_manager)
        self.headers_manager = SecurityHeadersManager()

    def process_request(
        self,
        request_data: Dict[str, Any],
        validation_rules: Dict[str, str]
    ) -> Tuple[bool, Dict[str, Any], List[str]]:
        """
        Process and validate incoming request
        Returns (is_valid, sanitized_data, errors)
        """
        sanitized_data = {}
        errors = []

        for field, rule_name in validation_rules.items():
            if field not in request_data:
                continue

            value = str(request_data[field])
            result, sanitized, error = self.input_validator.validate(value, rule_name)

            if result == ValidationResult.BLOCKED:
                errors.append(f"{field}: {error}")
                logger.warning(f"Blocked input for field {field}")
            elif result == ValidationResult.INVALID:
                errors.append(f"{field}: {error}")
            else:
                sanitized_data[field] = sanitized

        return len(errors) == 0, sanitized_data, errors

    def prepare_response(
        self,
        response_data: Dict[str, Any],
        page_type: str = 'standard',
        encrypt_sensitive: bool = False,
        sensitive_fields: Optional[List[str]] = None
    ) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """
        Prepare response with security headers and optional encryption
        Returns (processed_data, headers)
        """
        # Get security headers
        nonce = self.csp_manager.generate_nonce(str(uuid.uuid4()))
        headers = self.headers_manager.get_security_headers(page_type, nonce)

        # Encrypt sensitive fields if requested
        processed_data = response_data.copy()
        if encrypt_sensitive and sensitive_fields:
            for field in sensitive_fields:
                if field in processed_data:
                    encrypted = self.encryption_manager.encrypt(
                        str(processed_data[field]).encode('utf-8'),
                        'pii_encryption'
                    )
                    processed_data[field] = encrypted

        return processed_data, headers

    def create_secure_session(
        self,
        user_id: str,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str,
        organization_id: Optional[str] = None
    ) -> Tuple[SecureSession, Dict[str, Any]]:
        """
        Create secure session with cookie options
        Returns (session, cookie_options)
        """
        session = self.session_manager.create_session(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            organization_id=organization_id,
        )

        cookie_options = self.session_manager.get_session_cookie_options()

        return session, cookie_options

    def validate_and_refresh_session(
        self,
        session_id: str,
        ip_address: str,
        user_agent: str
    ) -> Tuple[bool, Optional[SecureSession], str]:
        """Validate session and refresh if needed"""
        return self.session_manager.validate_session(session_id, ip_address, user_agent)

    def get_security_status(self) -> Dict[str, Any]:
        """Get overall security status"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'csp_policies': list(self.csp_manager.policies.keys()),
            'hsts_enabled': True,
            'hsts_max_age': self.hsts_manager.config['max_age'],
            'encryption_keys': {
                purpose: {
                    'key_id': key.key_id,
                    'algorithm': key.algorithm.value,
                    'status': key.status,
                    'expires_at': key.expires_at.isoformat() if key.expires_at else None,
                }
                for purpose, key in self.encryption_manager.keys.items()
            },
            'keys_due_for_rotation': len(self.encryption_manager.get_keys_due_for_rotation()),
            'active_sessions': len([s for s in self.session_manager.sessions.values() if s.state == SessionState.ACTIVE]),
            'validation_rules': list(self.input_validator.rules.keys()),
        }


# Middleware decorator for security hardening
def security_hardened(
    page_type: str = 'standard',
    validation_rules: Optional[Dict[str, str]] = None,
    require_session: bool = True
):
    """Decorator to apply security hardening to endpoints"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            hardening = kwargs.get('security_hardening')
            if not hardening:
                raise ValueError("Security hardening engine not provided")

            request_data = kwargs.get('request_data', {})

            # Validate input
            if validation_rules:
                is_valid, sanitized, errors = hardening.process_request(
                    request_data, validation_rules
                )
                if not is_valid:
                    raise ValueError(f"Validation failed: {errors}")
                kwargs['request_data'] = sanitized

            # Execute function
            result = func(*args, **kwargs)

            # Add security headers to response
            if isinstance(result, dict):
                _, headers = hardening.prepare_response({}, page_type)
                result['_security_headers'] = headers

            return result
        return wrapper
    return decorator


# Example usage
if __name__ == "__main__":
    # Initialize Fraud Fusion Security Hardening
    hardening = FraudFusionSecurityHardening()

    # Test input validation
    test_inputs = {
        'email': ('test@example.com', 'email'),
        'phone': ('+2348012345678', 'phone_ng'),
        'bvn': ('12345678901', 'bvn'),
        'amount': ('50000.50', 'amount'),
    }

    print("Input Validation Tests:")
    for field, (value, rule) in test_inputs.items():
        result, sanitized, error = hardening.input_validator.validate(value, rule)
        print(f"  {field}: {result.value} - {sanitized if result == ValidationResult.VALID else error}")

    # Test session creation
    session, cookie_opts = hardening.create_secure_session(
        user_id="user-123",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 Chrome/120.0.0.0",
        device_fingerprint="fp-abc123",
        organization_id="org-456",
    )
    print(f"\nSession created: {session.session_id[:30]}...")

    # Get security status
    status = hardening.get_security_status()
    print(f"\nSecurity Status:")
    print(f"  Active Sessions: {status['active_sessions']}")
    print(f"  Encryption Keys: {len(status['encryption_keys'])}")
    print(f"  Validation Rules: {len(status['validation_rules'])}")

    print("\nFraud Fusion Security Hardening initialized successfully")
