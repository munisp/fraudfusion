"""
Security Manager for FraudFusion Platform

This module provides comprehensive security features including authentication,
authorization, encryption, input validation, and security auditing.
"""

import hashlib
import hmac
import os
import threading
import secrets
import jwt
import bcrypt
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from contextlib import contextmanager
import logging
import re
from enum import Enum
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import ipaddress

# psycopg2 is required only when the durable repository is actually used; the
# import is deferred so role/permission, rate-limiter and JWT unit tests can
# run without a database driver installed.
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:  # pragma: no cover - environment without psycopg2
    psycopg2 = None
    RealDictCursor = None

logger = logging.getLogger(__name__)

class Role(Enum):
    """User roles for authorization"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API_USER = "api_user"

class Permission(Enum):
    """Granular permissions"""
    READ_TRANSACTIONS = "read:transactions"
    WRITE_TRANSACTIONS = "write:transactions"
    READ_MODELS = "read:models"
    WRITE_MODELS = "write:models"
    TRAIN_MODELS = "train:models"
    DEPLOY_MODELS = "deploy:models"
    READ_USERS = "read:users"
    WRITE_USERS = "write:users"
    READ_AUDIT = "read:audit"
    ADMIN_ALL = "admin:all"

@dataclass
class SecurityConfig:
    """Security configuration.

    JWT secrets are NEVER generated per-process: `jwt_secret` must come from
    the JWT_SECRET environment variable (or be passed explicitly), otherwise
    SecurityManager refuses to boot (fail-closed). A random per-process secret
    would invalidate every token on restart and let each replica mint tokens
    the others accept.

    Rotation procedure (documented for operators):
      1. Generate a new secret, deploy it as JWT_SECRET_PREVIOUS=<old>,
         JWT_SECRET=<new> — verify_token accepts both during the window.
      2. After the longest token lifetime (jwt_expiration_hours) has elapsed,
         remove JWT_SECRET_PREVIOUS. Tokens minted with the old secret are
         then rejected.
    """
    jwt_secret: str = ""
    jwt_previous_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24
    password_min_length: int = 12
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digits: bool = True
    password_require_special: bool = True
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    session_timeout_minutes: int = 60
    enable_2fa: bool = True
    allowed_ip_ranges: List[str] = None
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    database_url: Optional[str] = None
    redis_url: Optional[str] = None

    def __post_init__(self):
        if not self.jwt_secret:
            self.jwt_secret = os.getenv("JWT_SECRET", "").strip()
        if not self.jwt_previous_secret:
            self.jwt_previous_secret = os.getenv("JWT_SECRET_PREVIOUS", "").strip()
        if not self.redis_url:
            self.redis_url = os.getenv("REDIS_URL", "").strip() or None

class PasswordValidator:
    """
    Validates password strength and complexity
    """

    def __init__(self, config: SecurityConfig):
        self.config = config

    def validate(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password against security policy

        Returns:
            (is_valid, error_messages)
        """
        errors = []

        # Length check
        if len(password) < self.config.password_min_length:
            errors.append(f"Password must be at least {self.config.password_min_length} characters")

        # Uppercase check
        if self.config.password_require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")

        # Lowercase check
        if self.config.password_require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")

        # Digit check
        if self.config.password_require_digits and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")

        # Special character check
        if self.config.password_require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")

        # Common password check
        if self._is_common_password(password):
            errors.append("Password is too common")

        return len(errors) == 0, errors

    def _is_common_password(self, password: str) -> bool:
        """Check against common passwords"""
        common_passwords = {
            'password', 'password123', '123456', 'qwerty', 'admin',
            'letmein', 'welcome', 'monkey', '1234567890'
        }
        return password.lower() in common_passwords

class PasswordHasher:
    """
    Secure password hashing using bcrypt
    """

    def __init__(self, rounds: int = 12):
        self.rounds = rounds

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=self.rounds)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False

class JWTManager:
    """
    JWT token management for authentication
    """

    def __init__(self, config: SecurityConfig):
        self.config = config

    def create_token(self, user_id: str, role: Role,
                    additional_claims: Dict[str, Any] = None) -> str:
        """Create JWT token"""
        expiration = datetime.utcnow() + timedelta(hours=self.config.jwt_expiration_hours)

        payload = {
            'user_id': user_id,
            'role': role.value,
            'exp': expiration,
            'iat': datetime.utcnow(),
            'jti': secrets.token_urlsafe(16)  # JWT ID for revocation
        }

        if additional_claims:
            payload.update(additional_claims)

        token = jwt.encode(payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm)
        return token

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token.

        During rotation (JWT_SECRET_PREVIOUS set) tokens signed with the
        previous secret are still accepted until the rotation window closes.
        """
        secrets_to_try = [self.config.jwt_secret]
        if self.config.jwt_previous_secret:
            secrets_to_try.append(self.config.jwt_previous_secret)
        for secret in secrets_to_try:
            try:
                return jwt.decode(token, secret, algorithms=[self.config.jwt_algorithm])
            except jwt.ExpiredSignatureError:
                logger.warning("Token expired")
                return None
            except jwt.InvalidTokenError:
                continue  # try the previous secret, if any
        logger.warning("Invalid token: signature rejected by all configured secrets")
        return None

    def refresh_token(self, token: str) -> Optional[str]:
        """Refresh token if valid"""
        payload = self.verify_token(token)
        if payload:
            return self.create_token(
                payload['user_id'],
                Role(payload['role'])
            )
        return None

class EncryptionManager:
    """
    Data encryption and decryption
    """

    def __init__(self, master_key: Optional[bytes] = None):
        if master_key:
            self.key = master_key
        else:
            self.key = Fernet.generate_key()

        self.cipher = Fernet(self.key)

    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        encrypted = self.cipher.encrypt(data.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        try:
            decoded = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise ValueError("Failed to decrypt data")

    def encrypt_dict(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Encrypt dictionary values"""
        return {k: self.encrypt(str(v)) for k, v in data.items()}

    def decrypt_dict(self, encrypted_data: Dict[str, str]) -> Dict[str, str]:
        """Decrypt dictionary values"""
        return {k: self.decrypt(v) for k, v in encrypted_data.items()}

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

class InputValidator:
    """
    Input validation and sanitization
    """

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username format"""
        # Alphanumeric, underscore, hyphen, 3-32 characters
        pattern = r'^[a-zA-Z0-9_-]{3,32}$'
        return bool(re.match(pattern, username))

    @staticmethod
    def sanitize_string(input_str: str) -> str:
        """Sanitize string input"""
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>\"\'%;()&+]', '', input_str)
        return sanitized.strip()

    @staticmethod
    def validate_sql_injection(input_str: str) -> bool:
        """Check for SQL injection patterns"""
        sql_patterns = [
            r'(\bUNION\b.*\bSELECT\b)',
            r'(\bSELECT\b.*\bFROM\b)',
            r'(\bINSERT\b.*\bINTO\b)',
            r'(\bDELETE\b.*\bFROM\b)',
            r'(\bDROP\b.*\bTABLE\b)',
            r'(--)',
            r'(;)',
            r'(\bOR\b.*=.*)',
        ]

        for pattern in sql_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                return False
        return True

    @staticmethod
    def validate_xss(input_str: str) -> bool:
        """Check for XSS patterns"""
        xss_patterns = [
            r'<script',
            r'javascript:',
            r'onerror=',
            r'onload=',
            r'<iframe',
        ]

        for pattern in xss_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                return False
        return True

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

class RateLimiter:
    """
    Sliding-window rate limiting for API endpoints.

    Backend selection (honest, reported via `backend` and health()):
      * REDIS_URL configured and reachable -> Redis sorted-set sliding window
        (shared across all replicas, survives restarts). Backend "redis".
      * otherwise -> per-process in-memory window. Backend "memory"; this is
        a degradation (limits are per-process) and is reported loudly in
        health checks.
    Redis errors fail CLOSED (request denied + error logged): a rate limiter
    that silently opens up on outage is an auth-bruteforce enabler.
    """

    REDIS_KEY_PREFIX = "ff:ratelimit:"

    def __init__(self, config: SecurityConfig, redis_client=None):
        self.config = config
        self.requests = {}  # {identifier: [(timestamp, count)]} (memory backend)
        self._redis = None
        self.backend = "memory"
        if redis_client is not None:
            self._redis = redis_client
            self.backend = "redis"
        elif config.redis_url:
            try:
                import redis as redis_lib

                client = redis_lib.Redis.from_url(
                    config.redis_url, socket_timeout=2.0, socket_connect_timeout=2.0
                )
                client.ping()
                self._redis = client
                self.backend = "redis"
                logger.info("RateLimiter using Redis sliding window (%s)", config.redis_url)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "REDIS_URL is set (%s) but Redis is unusable: %s. "
                    "Falling back to per-process in-memory rate limiting (backend: memory).",
                    config.redis_url, exc,
                )

    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed"""
        if self._redis is not None:
            return self._is_allowed_redis(identifier)
        return self._is_allowed_memory(identifier)

    def _is_allowed_redis(self, identifier: str) -> bool:
        import time as _time

        key = self.REDIS_KEY_PREFIX + identifier
        now_ms = int(_time.time() * 1000)
        window_ms = self.config.rate_limit_window_seconds * 1000
        try:
            pipe = self._redis.pipeline(transaction=True)
            pipe.zremrangebyscore(key, 0, now_ms - window_ms)
            pipe.zcard(key)
            pipe.zadd(key, {f"{now_ms}:{secrets.token_hex(4)}": now_ms})
            pipe.expire(key, self.config.rate_limit_window_seconds + 1)
            _, count, _, _ = pipe.execute()
        except Exception as exc:  # noqa: BLE001
            # Fail closed: deny the request rather than disabling the control.
            logger.error("Redis rate limiter error for %s (%s) — denying request", identifier, exc)
            return False
        if count >= self.config.rate_limit_requests:
            logger.warning(f"Rate limit exceeded for {identifier}")
            return False
        return True

    def _is_allowed_memory(self, identifier: str) -> bool:
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.config.rate_limit_window_seconds)

        # Clean old entries
        if identifier in self.requests:
            self.requests[identifier] = [
                (ts, count) for ts, count in self.requests[identifier]
                if ts > window_start
            ]
        else:
            self.requests[identifier] = []

        # Count requests in window
        total_requests = sum(count for _, count in self.requests[identifier])

        if total_requests >= self.config.rate_limit_requests:
            logger.warning(f"Rate limit exceeded for {identifier}")
            return False

        # Add current request
        self.requests[identifier].append((now, 1))
        return True

    def health(self) -> Dict[str, Any]:
        """Honest backend reporting for health endpoints."""
        return {
            "backend": self.backend,
            "window_seconds": self.config.rate_limit_window_seconds,
            "max_requests": self.config.rate_limit_requests,
            "degraded": self.backend == "memory" and bool(self.config.redis_url),
        }

class IPWhitelist:
    """
    IP address whitelisting
    """

    def __init__(self, allowed_ranges: List[str]):
        self.allowed_networks = []
        for range_str in allowed_ranges or []:
            try:
                self.allowed_networks.append(ipaddress.ip_network(range_str))
            except ValueError:
                logger.error(f"Invalid IP range: {range_str}")

    def is_allowed(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        if not self.allowed_networks:
            return True  # No whitelist configured

        try:
            ip_addr = ipaddress.ip_address(ip)
            for network in self.allowed_networks:
                if ip_addr in network:
                    return True
            return False
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False

class AuditLogger:
    """
    Security audit logging.

    Events are persisted to the `security_audit_log` table (see
    database/20260901_python_services_caveats.sql) via the injected `persist`
    callable, AND kept in a bounded in-memory ring buffer (last
    `ring_capacity` events) which backs `get_events` reads. Persistence
    failures are logged at ERROR (loud) but never drop the in-memory event.
    """

    def __init__(self, persist=None, ring_capacity: int = 1000, tenant_id: str = "default"):
        from collections import deque

        self.audit_log = deque(maxlen=ring_capacity)  # in-mem ring for reads
        self._persist = persist
        self.tenant_id = tenant_id

    def log_event(self, event_type: str, user_id: str,
                  details: Dict[str, Any], ip_address: str = None):
        """Log security event"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'details': details
        }

        self.audit_log.append(event)
        if self._persist is not None:
            try:
                self._persist(event)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "AUDIT PERSISTENCE FAILED for event %s by %s: %s "
                    "(event retained only in volatile ring buffer)",
                    event_type, user_id, exc,
                )
        logger.info(f"Security event: {event_type} by {user_id}")

    def get_events(self, user_id: str = None,
                   event_type: str = None,
                   start_time: datetime = None,
                   end_time: datetime = None) -> List[Dict[str, Any]]:
        """Query the in-memory audit ring (durable history is in
        security_audit_log; query that for anything older than the ring)."""
        filtered = list(self.audit_log)

        if user_id:
            filtered = [e for e in filtered if e['user_id'] == user_id]

        if event_type:
            filtered = [e for e in filtered if e['event_type'] == event_type]

        if start_time:
            filtered = [e for e in filtered
                       if datetime.fromisoformat(e['timestamp']) >= start_time]

        if end_time:
            filtered = [e for e in filtered
                       if datetime.fromisoformat(e['timestamp']) <= end_time]

        return filtered

class AuthorizationManager:
    """
    Role-based access control (RBAC)
    """

    def __init__(self):
        # Role -> permission matrix. Audit remediation: ANALYST no longer holds
        # TRAIN_MODELS (model training is an ML-engineering function; analysts
        # consume models, they do not train them). A regression test pins this
        # matrix (implementations/security/tests/test_security_manager.py).
        self.role_permissions = {
            Role.ADMIN: [Permission.ADMIN_ALL],
            Role.ANALYST: [
                Permission.READ_TRANSACTIONS,
                Permission.WRITE_TRANSACTIONS,
                Permission.READ_MODELS,
                Permission.READ_AUDIT
            ],
            Role.VIEWER: [
                Permission.READ_TRANSACTIONS,
                Permission.READ_MODELS
            ],
            Role.API_USER: [
                Permission.READ_TRANSACTIONS,
                Permission.READ_MODELS
            ]
        }

    def has_permission(self, role: Role, permission: Permission) -> bool:
        """Check if role has permission"""
        if role == Role.ADMIN or Permission.ADMIN_ALL in self.role_permissions.get(role, []):
            return True

        return permission in self.role_permissions.get(role, [])

    def require_permission(self, role: Role, permission: Permission):
        """Decorator to require permission"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                if not self.has_permission(role, permission):
                    raise PermissionError(f"Role {role.value} lacks permission {permission.value}")
                return func(*args, **kwargs)
            return wrapper
        return decorator

class SecurityManager:
    """
    Comprehensive security manager
    """

    def __init__(self, config: SecurityConfig = None):
        self.config = config or SecurityConfig()

        # Fail closed: booting without an operator-provided JWT secret would
        # mean either a random per-process secret (tokens invalid across
        # replicas/restarts) or an empty HMAC key. Neither is acceptable.
        if not self.config.jwt_secret:
            raise ValueError(
                "JWT_SECRET must be configured for SecurityManager "
                "(random per-process secrets are forbidden; see SecurityConfig "
                "docstring for the rotation procedure via JWT_SECRET_PREVIOUS)"
            )

        self.password_validator = PasswordValidator(self.config)
        self.password_hasher = PasswordHasher()
        self.jwt_manager = JWTManager(self.config)
        self.encryption_manager = EncryptionManager()
        self.input_validator = InputValidator()
        self.rate_limiter = RateLimiter(self.config)
        self.ip_whitelist = IPWhitelist(self.config.allowed_ip_ranges)
        self.authorization_manager = AuthorizationManager()
        self.database_url = self.config.database_url or os.getenv("DATABASE_URL", "").strip()
        self._conn_pool = None
        self._pool_lock = threading.Lock()
        if not self.database_url:
            raise ValueError("DATABASE_URL must be configured for SecurityManager")
        self.audit_logger = AuditLogger(persist=self._persist_audit_event)

        logger.info(
            "Security Manager initialized (durable auth repository, rate-limiter backend: %s)",
            self.rate_limiter.backend,
        )

    def health(self) -> Dict[str, Any]:
        """Honest component health: rate-limiter backend is reported loudly so
        a memory fallback (per-process limits) is never silent."""
        return {
            "status": "healthy",
            "rate_limiter": self.rate_limiter.health(),
            "audit": {"backend": "postgres+memory-ring", "table": "security_audit_log"},
            "jwt": {
                "algorithm": self.config.jwt_algorithm,
                "rotation_window_open": bool(self.config.jwt_previous_secret),
            },
        }

    def _persist_audit_event(self, event: Dict[str, Any]) -> None:
        """Write one audit event to the durable security_audit_log table."""
        import json as _json

        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO security_audit_log (event_type, user_id, ip_address, details)"
                    " VALUES (%s, %s, %s, %s)",
                    (
                        event["event_type"], event["user_id"],
                        event.get("ip_address"), _json.dumps(event.get("details") or {}),
                    ),
                )

    def register_user(self, username: str, password: str, email: str,
                     role: Role = Role.VIEWER) -> Dict[str, Any]:
        """Register new user with security validation"""
        # Validate inputs
        if not self.input_validator.validate_username(username):
            raise ValueError("Invalid username format")

        if not self.input_validator.validate_email(email):
            raise ValueError("Invalid email format")

        # Validate password
        is_valid, errors = self.password_validator.validate(password)
        if not is_valid:
            raise ValueError(f"Password validation failed: {', '.join(errors)}")

        # Hash password
        password_hash = self.password_hasher.hash_password(password)

        encrypted_email = self.encryption_manager.encrypt(email)
        with self._connection() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    """
                    INSERT INTO security_users (username, password_hash, email_encrypted, role, is_active, is_locked, created_at)
                    VALUES (%s,%s,%s,%s,TRUE,FALSE,NOW())
                    RETURNING username, role, is_active, is_locked, created_at
                    """,
                    (username, password_hash, encrypted_email, role.value),
                )
                user = dict(cursor.fetchone())
        self.audit_logger.log_event('user_registered', username, {'role': role.value})
        return user

    def authenticate_user(self, username: str, password: str,
                         ip_address: str = None) -> Optional[str]:
        """Authenticate user and return JWT token"""
        # Check IP whitelist
        if ip_address and not self.ip_whitelist.is_allowed(ip_address):
            self.audit_logger.log_event('auth_failed', username,
                                       {'reason': 'ip_not_whitelisted'}, ip_address)
            raise PermissionError("IP address not whitelisted")

        # Check rate limiting
        if not self.rate_limiter.is_allowed(username):
            self.audit_logger.log_event('auth_failed', username,
                                       {'reason': 'rate_limited'}, ip_address)
            raise PermissionError("Rate limit exceeded")

        # Check account lockout
        if self._is_account_locked(username):
            self.audit_logger.log_event('auth_failed', username,
                                       {'reason': 'account_locked'}, ip_address)
            raise PermissionError("Account is locked")

        # Verify password (in production, fetch from database)
        # This is a simplified example
        user = self._get_user(username)
        if not user:
            self._record_failed_login(username, ip_address)
            return None

        if not self.password_hasher.verify_password(password, user['password_hash']):
            self._record_failed_login(username, ip_address)
            self.audit_logger.log_event('auth_failed', username,
                                       {'reason': 'invalid_password'}, ip_address)
            return None

        self._clear_failed_logins(username)

        # Create JWT token
        token = self.jwt_manager.create_token(username, Role(user['role']))

        self.audit_logger.log_event('auth_success', username, {}, ip_address)

        return token

    def validate_request(self, token: str, required_permission: Permission = None,
                        ip_address: str = None) -> bool:
        """Validate request with token and permissions"""
        # Verify token
        payload = self.jwt_manager.verify_token(token)
        if not payload:
            return False

        # Check IP whitelist
        if ip_address and not self.ip_whitelist.is_allowed(ip_address):
            return False

        # Check permission
        if required_permission:
            role = Role(payload['role'])
            if not self.authorization_manager.has_permission(role, required_permission):
                return False

        return True

    def _pool(self):
        """Lazily created thread-safe connection pool. Previously every
        operation opened a brand-new connection (TCP+TLS+auth handshake,
        ~5-30ms each; authenticate_user made up to 4 per login)."""
        if psycopg2 is None:
            raise RuntimeError(
                "psycopg2 is not installed; SecurityManager's durable repository "
                "requires psycopg2-binary (see service requirements)"
            )
        if self._conn_pool is None:
            with self._pool_lock:
                if self._conn_pool is None:
                    from psycopg2 import pool as _pg_pool

                    self._conn_pool = _pg_pool.ThreadedConnectionPool(
                        minconn=int(os.environ.get("SECURITY_DB_POOL_MIN", "2")),
                        maxconn=int(os.environ.get("SECURITY_DB_POOL_MAX", "10")),
                        dsn=self.database_url,
                        connect_timeout=5,
                    )
        return self._conn_pool

    @contextmanager
    def _connection(self):
        connection = self._pool().getconn()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            self._pool().putconn(connection)

    def _get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieve only active, unlocked users through a parameterized database query."""
        with self._connection() as connection:
            with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT username, password_hash, role, is_active, is_locked FROM security_users WHERE username=%s",
                    (username,),
                )
                row = cursor.fetchone()
        if not row or not row['is_active'] or row['is_locked']:
            return None
        return dict(row)

    def _record_failed_login(self, username: str, ip_address: Optional[str]):
        """Persist a failed authentication attempt for cross-process lockout enforcement."""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO security_login_failures (username, ip_address, attempted_at) VALUES (%s,%s,NOW())",
                    (username, ip_address),
                )

    def _clear_failed_logins(self, username: str):
        """Tombstone (soft-clear) failure rows after a successful verified
        password check. Anti-wipe policy: failed-login rows are attack evidence
        and are never hard-deleted by this service; they are marked
        cleared_at/cleared_by and stay in the table for forensics. Physical
        removal is possible only via the dual-control deletion_approvals +
        execute_approved_hard_delete path (database/20260825_antiwipe_soft_delete.sql)."""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE security_login_failures SET cleared_at = NOW(), cleared_by = %s"
                    " WHERE username = %s AND cleared_at IS NULL",
                    (username, username),
                )

    def _is_account_locked(self, username: str) -> bool:
        """Determine lockout from durable failures within the configured policy window."""
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM security_login_failures
                    WHERE username=%s AND cleared_at IS NULL
                      AND attempted_at >= NOW() - (%s * INTERVAL '1 minute')
                    """,
                    (username, self.config.lockout_duration_minutes),
                )
                failures = cursor.fetchone()[0]
        return failures >= self.config.max_login_attempts

def main():
    """Example usage"""
    config = SecurityConfig()
    security_manager = SecurityManager(config)

    # Register user
    try:
        user = security_manager.register_user(
            username="john_doe",
            password="SecureP@ssw0rd123!",
            email="john@example.com",
            role=Role.ANALYST
        )
        logger.info(f"User registered: {user['username']}")
    except ValueError as e:
        logger.error(f"Registration failed: {e}")

    # Authenticate
    token = security_manager.authenticate_user("john_doe", "SecureP@ssw0rd123!", "192.168.1.1")
    if token:
        logger.info("Authentication successful")

    # Validate request
    is_valid = security_manager.validate_request(token, Permission.READ_TRANSACTIONS)
    logger.info(f"Request validation: {is_valid}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
