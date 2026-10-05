"""
M-PESA Service Integration
Handles Safaricom Daraja API integration for M-PESA payments
"""
import base64
import datetime
import math
import requests
import json
import time
import hashlib
import hmac
import os
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class MpesaService:
    """Safaricom Daraja API service for M-PESA payments"""

    SUCCESS = "0"
    USER_CANCELLED = "1032"
    TIMEOUT = "1037"
    REJECTED = "2001"  # Initiator information invalid (wrong PIN / credentials)
    INVALID_PIN = "1014"
    INVALID_PHONE = "20001"
    INSUFFICIENT_FUNDS = "20003"
    SYSTEM_ERROR = "9999"

    RESULT_CODE_MESSAGES = {
        SUCCESS: 'Payment completed successfully',
        '1001': 'Unable to process request',
        '1002': 'Invalid account number',
        INVALID_PIN: 'Invalid PIN entered',
        REJECTED: 'Payment was rejected; please verify your PIN and try again',
        INVALID_PHONE: 'Invalid phone number',
        INSUFFICIENT_FUNDS: 'Insufficient funds',
        # 1032 = the customer cancelled/rejected the STK request.
        # 1037 = the STK request timed out (no decision reached in time).
        # These are distinct outcomes and are surfaced as distinct states.
        USER_CANCELLED: 'Payment cancelled by user',
        TIMEOUT: 'Payment request timed out',
        '20004': 'User cancelled the transaction',
        SYSTEM_ERROR: 'System error; please try again later'
    }
    
    def __init__(self):
        # Load from environment variables
        self.consumer_key = os.getenv('MPESA_CONSUMER_KEY', '').strip()
        self.consumer_secret = os.getenv('MPESA_CONSUMER_SECRET', '').strip()
        self.passkey = os.getenv('MPESA_PASSKEY', '').strip()
        self.business_shortcode = os.getenv('MPESA_SHORTCODE')
        self.account_reference = os.getenv('MPESA_ACCOUNT_REFERENCE', 'DigitalProducts')
        self.transaction_desc = os.getenv('MPESA_TRANSACTION_DESC', 'Digital Product Purchase')
        self.callback_url = os.getenv('MPESA_CALLBACK_URL', '')
        self.environment = os.getenv('MPESA_ENVIRONMENT', 'sandbox').lower()  # sandbox or production
        
        # API endpoints must come from environment variables
        self.oauth_url = os.getenv('MPESA_AUTH_URL')
        self.stkpush_url = os.getenv('MPESA_STK_PUSH_URL')
        self.query_url = os.getenv('MPESA_QUERY_URL')

        # Guard against sandbox/production credential mixing: warn loudly if the
        # configured environment does not match the host in the Daraja URLs.
        if self.oauth_url and self.stkpush_url:
            expected_host = 'sandbox.safaricom.co.ke' if self.environment == 'sandbox' else 'api.safaricom.co.ke'
            if expected_host not in self.oauth_url or expected_host not in self.stkpush_url:
                self._log_warning(
                    'AUTH',
                    f"MPESA_ENVIRONMENT={self.environment} but MPESA_AUTH_URL / MPESA_STK_PUSH_URL "
                    f"do not both reference {expected_host} - sandbox/production credentials may be mixed"
                )
        
        allowed_ips = os.getenv('MPESA_CALLBACK_ALLOWED_IPS', '').strip()
        if allowed_ips:
            self.allowed_callback_ips = [ip.strip() for ip in allowed_ips.split(',') if ip.strip()]
        elif self.environment == 'sandbox':
            self.allowed_callback_ips = [
                '196.201.214.200', '196.201.214.201', '196.201.214.202', '196.201.214.203'
            ]
        else:
            # Production has NO mandatory allowlist: Safaricom does not publish
            # stable callback IPs, so an unset list must not block the service.
            self.allowed_callback_ips = []

        self.max_amount = self._load_max_amount()
        self._validate_configuration()
        
        self.access_token = None
        self.token_expiry = None
        self._payment_sequence = 0
        self.session = requests.Session()
    
    def get_access_token(self) -> Optional[str]:
        """Get OAuth access token from Safaricom Daraja API.

        Per the Daraja OAuth spec the Authorization header is
        ``Basic base64("consumer_key:consumer_secret")``. The returned
        ``access_token`` is cached for 50 minutes and reused across STK push and
        transaction-query calls.
        """
        if self.access_token and self.token_expiry and self.token_expiry > datetime.datetime.now():
            return self.access_token

        try:
            self._log_info('AUTH', 'Getting access token')
            self._log_info('AUTH', f"OAuth request: GET {self.oauth_url}")
            self._log_info(
                'AUTH',
                f"Basic auth: base64(consumer_key:consumer_secret) "
                f"key_prefix={self.consumer_key[:4]}… len={len(self.consumer_key)}",
            )

            credentials = base64.b64encode(
                f"{self.consumer_key}:{self.consumer_secret}".encode("utf-8")
            ).decode("ascii")
            headers = {
                "Authorization": f"Basic {credentials}",
                "Accept": "application/json",
            }

            response = self._perform_daraja_request(
                'get',
                self.oauth_url,
                headers=headers,
                timeout=30
            )

            self._log_info('AUTH', f"Token response status: {response.status_code}")
            self._log_info('AUTH', f"Token response content type: {response.headers.get('content-type', 'unknown')}")

            response.raise_for_status()

            try:
                token_data = response.json()
            except ValueError as e:
                self._log_error('AUTH', f"Failed to parse token response as JSON: {str(e)}")
                self._log_error('AUTH', f"Token response status: {response.status_code}")
                self._log_error('AUTH', f"Token response content type: {response.headers.get('content-type', 'unknown')}")
                self._log_error('AUTH', f"Token response text (first 500 chars): {response.text[:500]}")
                return None

            if not isinstance(token_data, dict):
                self._log_error('AUTH', f"OAuth response was not a JSON object: {type(token_data).__name__}")
                return None

            token = token_data.get('access_token')
            if not token:
                self._log_error('AUTH', 'OAuth response did not contain an access_token')
                self._log_error('AUTH', f"OAuth response keys: {sorted(token_data.keys())}")
                self._log_error('AUTH', f"OAuth response text (first 500 chars): {response.text[:500]}")
                return None

            self.access_token = token
            self.token_expiry = datetime.datetime.now() + datetime.timedelta(minutes=50)
            self._log_info('AUTH', f"Access token obtained (len={len(token)}, prefix={token[:6]}…)")
            return self.access_token

        except (requests.exceptions.RequestException, ValueError) as e:
            self._log_error('AUTH', f"Error getting access token: {str(e)}")
            return None

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """Redact a secret for logging: short prefix + length only."""
        if not secret:
            return '<empty>'
        return f"{secret[:6]}…({len(secret)} chars)"

    @staticmethod
    def _mask_headers(headers: Dict[str, str]) -> str:
        """Render request headers for logs with the Authorization value redacted."""
        masked = {}
        for key, value in headers.items():
            if key.lower() == 'authorization':
                scheme, _, rest = value.partition(' ')
                masked[key] = f"{scheme} {MpesaService._mask_secret(rest)}"
            else:
                masked[key] = value
        return json.dumps(masked)

    @staticmethod
    def _bearer_headers(access_token: str) -> Dict[str, str]:
        """Build the Authorization header for Daraja STK push/query requests."""
        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

    def _perform_daraja_request(self, method: str, url: str, *, max_retries: int = 3, retry_delay: float = 0.5, **kwargs) -> requests.Response:
        """Perform a Daraja API request with retry on temporary failures."""
        attempt = 1
        while True:
            try:
                if method.lower() == 'get':
                    response = self.session.get(url, **kwargs)
                elif method.lower() == 'post':
                    response = self.session.post(url, **kwargs)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")

                if response.status_code in (500, 502, 503):
                    self._log_warning('RETRY', f"Temporary server error {response.status_code} on {method} {url}")
                    if attempt >= max_retries:
                        response.raise_for_status()
                        return response
                    time.sleep(retry_delay * attempt)
                    attempt += 1
                    continue

                return response
            except requests.exceptions.Timeout as e:
                self._log_warning('RETRY', f"Timeout during Daraja request ({str(e)}). Retry {attempt}/{max_retries}")
                if attempt >= max_retries:
                    raise
                time.sleep(retry_delay * attempt)
                attempt += 1
            except requests.exceptions.RequestException:
                raise

    def generate_password(self, timestamp: str) -> str:
        """Generate Daraja API password"""
        data = f"{self.business_shortcode}{self.passkey}{timestamp}"
        return base64.b64encode(data.encode()).decode()

    def generate_transaction_reference(self) -> str:
        """Generate unique transaction reference"""
        timestamp = str(int(time.time() * 1000))
        return f"DP_{timestamp}"  # DP for Digital Products

    def generate_payment_id(self) -> str:
        """Generate a unique payment request ID for logging."""
        self._payment_sequence += 1
        sequence = f"{self._payment_sequence:03d}"
        return f"PAY_{datetime.datetime.now().strftime('%Y%m%d')}_{sequence}"

    def validate_phone_number(self, phone_number: str) -> Optional[str]:
        """Validate and format Kenyan mobile phone numbers for M-PESA."""
        if not phone_number:
            return None

        clean_phone = ''.join(filter(str.isdigit, phone_number))
        if not clean_phone:
            self._log_error('VALIDATION', f"Invalid M-PESA phone number format: {phone_number}")
            return None

        # Remove country code or leading zero, normalize to 9 digits
        if clean_phone.startswith('254'):
            clean_phone = clean_phone[3:]
        elif clean_phone.startswith('0'):
            clean_phone = clean_phone[1:]

        if len(clean_phone) != 9:
            self._log_error('VALIDATION', f"Invalid M-PESA phone number length: {phone_number}")
            return None

        if not clean_phone.startswith('7'):
            self._log_error('VALIDATION', f"Invalid M-PESA phone number prefix: {phone_number}")
            return None

        valid_prefixes = {
            '70', '71', '72', '73', '74', '75', '76', '77', '78', '79'
        }
        if clean_phone[:2] not in valid_prefixes:
            self._log_error('VALIDATION', f"Invalid M-PESA phone number prefix: {phone_number}")
            return None

        return f"254{clean_phone}"

    def _load_max_amount(self) -> int:
        """Load configurable maximum allowable M-PESA payment amount."""
        default_max = 100000
        raw_max = os.getenv('MPESA_MAX_AMOUNT', str(default_max)).strip()
        try:
            max_amount = int(raw_max)
            if max_amount <= 0:
                raise ValueError("Maximum amount must be positive")
            return max_amount
        except (TypeError, ValueError):
            self._log_warning('VALIDATION', f"M-PESA max amount env var invalid ({raw_max}); falling back to {default_max}")
            return default_max

    def _get_configuration_issues(self) -> list[str]:
        """Return a list of missing or invalid M-PESA configuration settings."""
        issues = []
        # NOTE: STK push is ALWAYS sent to the real Daraja API using the
        # credentials/endpoints from .env — sandbox keys when
        # MPESA_ENVIRONMENT=sandbox, live keys when =production. There is no
        # mock/offline mode. So all credentials and endpoints are validated here
        # based purely on the configured environment.
        if not self.consumer_key:
            issues.append('MPESA_CONSUMER_KEY')
        if not self.consumer_secret:
            issues.append('MPESA_CONSUMER_SECRET')
        if not self.passkey:
            issues.append('MPESA_PASSKEY')
        if not self.business_shortcode:
            issues.append('MPESA_SHORTCODE')
        elif not str(self.business_shortcode).isdigit():
            issues.append('MPESA_SHORTCODE must be numeric')
        elif not 5 <= len(str(self.business_shortcode).strip()) <= 7:
            issues.append('MPESA_SHORTCODE must be 5 to 7 digits')
        if not self.oauth_url:
            issues.append('MPESA_AUTH_URL')
        if not self.stkpush_url:
            issues.append('MPESA_STK_PUSH_URL')
        if not self.query_url:
            issues.append('MPESA_QUERY_URL')
        if self.environment == 'production':
            if not self.callback_url:
                issues.append('MPESA_CALLBACK_URL')
            # MPESA_CALLBACK_ALLOWED_IPS is deliberately NOT required here:
            # Safaricom does not publish stable production callback IPs, and a
            # mandatory allowlist would hard-fail the payment service on boot.
            # Callback authenticity instead relies on the CheckoutRequestID
            # lookup in the callback handler; if a real allowlist is configured
            # it is still enforced by validate_callback_origin().
        return issues

    def _validate_configuration(self) -> None:
        issues = self._get_configuration_issues()
        if issues:
            raise RuntimeError(
                f"M-PESA service configuration invalid in {self.environment} environment. "
                f"Missing or invalid settings: {', '.join(issues)}"
            )

    def _log(self, level: int, stage: str, message: str, payment_id: Optional[str] = None, *args, **kwargs) -> None:
        prefix = f"[M-PESA][{stage}]"
        if payment_id:
            prefix += f"[{payment_id}]"
        logger.log(level, f"{prefix} {message}", *args, **kwargs)

    def _log_info(self, stage: str, message: str, payment_id: Optional[str] = None, *args, **kwargs) -> None:
        self._log(logging.INFO, stage, message, payment_id, *args, **kwargs)

    def _log_debug(self, stage: str, message: str, payment_id: Optional[str] = None, *args, **kwargs) -> None:
        self._log(logging.DEBUG, stage, message, payment_id, *args, **kwargs)

    def _log_warning(self, stage: str, message: str, payment_id: Optional[str] = None, *args, **kwargs) -> None:
        self._log(logging.WARNING, stage, message, payment_id, *args, **kwargs)

    def _log_error(self, stage: str, message: str, payment_id: Optional[str] = None, *args, **kwargs) -> None:
        self._log(logging.ERROR, stage, message, payment_id, *args, **kwargs)

    def validate_amount(self, amount: Any) -> Optional[int]:
        """Validate payment amount before sending to Daraja.

        Safaricom M-PESA only accepts whole-number amounts (KES), so any
        decimal amount is rounded UP to the next whole number (e.g.
        KSh 905.68 -> 906) rather than rejected.
        """
        if isinstance(amount, bool):
            self._log_error('VALIDATION', 'Invalid M-PESA amount: boolean values are not permitted')
            return None

        try:
            amount_value = float(amount)
        except (TypeError, ValueError):
            self._log_error('VALIDATION', f"Invalid M-PESA amount: {amount}")
            return None

        if amount_value <= 0:
            self._log_error('VALIDATION', f"Invalid M-PESA amount: {amount_value} must be greater than zero")
            return None

        # M-PESA does not handle decimal amounts: round up to the next whole
        # number so a decimal subscription price (e.g. KSh 905.68) becomes the
        # next whole value (KSh 906) instead of failing the STK push.
        if amount_value != int(amount_value):
            amount_int = math.ceil(amount_value)
            self._log_info(
                'VALIDATION',
                f"Decimal M-PESA amount {amount_value} rounded up to {amount_int} "
                f"(Safaricom M-PESA requires whole-number amounts)"
            )
        else:
            amount_int = int(amount_value)

        if amount_int > self.max_amount:
            self._log_error('VALIDATION', f"Invalid M-PESA amount: {amount_int} exceeds maximum allowed amount {self.max_amount}")
            return None

        return amount_int

    def validate_shortcode(self) -> bool:
        """Validate that the configured business shortcode is numeric and correct length."""
        shortcode = str(self.business_shortcode or '').strip()
        if not shortcode.isdigit():
            self._log_error('VALIDATION', f"Invalid M-PESA shortcode: {self.business_shortcode}")
            return False

        if not 5 <= len(shortcode) <= 7:
            self._log_error('VALIDATION', f"Invalid M-PESA shortcode length: {shortcode} (expected 5 to 7 digits)")
            return False

        return True

    def validate_callback_origin(self, client_ip: str) -> bool:
        """Verify that the callback originated from an allowed Safaricom IP.

        The allowlist is OPTIONAL: Safaricom does not publish stable production
        callback IPs, so when MPESA_CALLBACK_ALLOWED_IPS is unset the origin
        check passes and authenticity relies on the callback structure plus the
        CheckoutRequestID/ConversationID matching a transaction we initiated.
        When an allowlist IS configured it is enforced fail-closed (unknown IPs
        are rejected). In sandbox the documented Safaricom sandbox IPs are used
        when nothing is configured.
        """
        if not self.allowed_callback_ips:
            if self.environment == 'production':
                self._log_debug(
                    'CALLBACK',
                    'No M-PESA callback IP allowlist configured - origin check skipped; '
                    'authenticity relies on CheckoutRequestID verification'
                )
            return True

        if client_ip not in self.allowed_callback_ips:
            self._log_warning('CALLBACK', f'Rejected callback from non-whitelisted IP: {client_ip}')
            return False
        return True

    def validate_callback_url(self, callback_url: str) -> bool:
        """Validate the M-PESA callback URL before sending STK Push.

        Only structural checks are performed here (non-empty, https scheme and
        a plausible host). We deliberately do NOT fire an outbound HEAD probe to
        the public URL: from inside the container that request hairpins back out
        through the public edge (Cloudflare/nginx) and is slow/unreliable — it
        routinely times out even when the endpoint is healthy, which blocked
        every production STK push (see the repeated "production URL unreachable
        (Read timed out)" errors). Daraja itself validates callback reachability
        when the STK push is submitted and returns an error result if the URL is
        bad, so a network probe here is both unnecessary and harmful.
        """
        if not callback_url:
            self._log_error('VALIDATION', 'Invalid M-PESA callback URL: empty')
            return False

        callback_url = str(callback_url).strip()
        if not callback_url.lower().startswith('https://'):
            self._log_error('VALIDATION', 'Invalid M-PESA callback URL: must start with https://')
            return False

        from urllib.parse import urlparse
        parsed = urlparse(callback_url)
        if not parsed.hostname or '.' not in parsed.hostname:
            self._log_error('VALIDATION', f'Invalid M-PESA callback URL: no plausible host in {callback_url}')
            return False

        return True

    def initiate_stk_push(self, phone_number: str, amount: float, 
                         account_reference: str = None, description: str = None) -> Optional[Dict[str, Any]]:
        """Initiate STK push to customer's phone.

        Always talks to the real Daraja API using the sandbox (or production)
        keys and endpoints from .env, selected only by MPESA_ENVIRONMENT. There
        is no mock/offline mode; every push is a real transaction request.
        """
        payment_id = self.generate_payment_id()
        self._log_info('STK_PUSH', 'Starting STK push initiation', payment_id)
        self._log_info('STK_PUSH', f"Phone: {phone_number}, Amount: {amount}", payment_id)

        access_token = self.get_access_token()
        if not access_token:
            self._log_error('STK_PUSH', 'Failed to get access token', payment_id)
            return None
        
        self._log_info('STK_PUSH', 'Access token obtained successfully', payment_id)

        if not self.validate_shortcode():
            return None

        # Validate phone number
        formatted_phone = self.validate_phone_number(phone_number)
        if not formatted_phone:
            return None

        # Validate amount before calling Daraja
        validated_amount = self.validate_amount(amount)
        if validated_amount is None:
            logger.error(f"[{payment_id}] Invalid M-PESA amount; aborting STK push")
            return None

        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        password = self.generate_password(timestamp)
        
        # Use provided callback URL or default
        callback_url = self.callback_url
        if not callback_url:
            # Try to construct from current app URL
            from flask import current_app
            if current_app:
                callback_url = f"{current_app.config.get('BASE_URL', '')}/api/mpesa/callback"
            else:
                self._log_error('STK_PUSH', 'Callback URL not configured', payment_id)
                return None

        if not self.validate_callback_url(callback_url):
            self._log_error('STK_PUSH', 'Callback URL validation failed', payment_id)
            return None
        
        payload = {
            "BusinessShortCode": self.business_shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": validated_amount,  # M-PESA expects integer amount
            "PartyA": formatted_phone,
            "PartyB": self.business_shortcode,
            "PhoneNumber": formatted_phone,
            "CallBackURL": callback_url,
            "AccountReference": account_reference or self.account_reference,
            "TransactionDesc": description or self.transaction_desc
        }

        headers = self._bearer_headers(access_token)

        try:
            self._log_info('STK_PUSH', f"Initiating STK push for {formatted_phone}, amount {amount}", payment_id)
            self._log_info('STK_PUSH', f"STK Push URL: {self.stkpush_url}", payment_id)
            self._log_info('STK_PUSH', f"Payload: {json.dumps(payload, indent=2)}", payment_id)
            self._log_info('STK_PUSH', f"Headers: {self._mask_headers(headers)}", payment_id)
            
            response = self._perform_daraja_request(
                'post',
                self.stkpush_url,
                headers=headers,
                json=payload,
                timeout=30
            )
            
            self._log_info('STK_PUSH', f"Response status code: {response.status_code}", payment_id)
            self._log_info('STK_PUSH', f"Response headers: {dict(response.headers)}", payment_id)
            self._log_info('STK_PUSH', f"Response content type: {response.headers.get('content-type', 'unknown')}", payment_id)
            self._log_info('STK_PUSH', f"Response text (first 500 chars): {response.text[:500]}", payment_id)
            
            response.raise_for_status()
            
            # Check if response is JSON before parsing
            try:
                result = response.json()
                self._log_info('STK_PUSH', f"STK push initiated: {result.get('ResponseCode')}", payment_id)
                return result
            except ValueError as e:
                # Handle JSON parsing errors (e.g., HTML responses)
                self._log_error('STK_PUSH', f"Failed to parse STK push response as JSON: {str(e)}", payment_id)
                self._log_error('STK_PUSH', f"Response status: {response.status_code}", payment_id)
                self._log_error('STK_PUSH', f"Response content type: {response.headers.get('content-type', 'unknown')}", payment_id)
                self._log_error('STK_PUSH', f"Response text (first 500 chars): {response.text[:500]}", payment_id)
                self._log_error('STK_PUSH', f"Full response text: {response.text}", payment_id)
                # Return error result for HTML responses
                return {
                    'ResponseCode': 1,
                    'ResultDesc': 'Failed to parse API response',
                    'errorMessage': f'Invalid JSON response: {str(e)}'
                }
            except (requests.exceptions.RequestException, ValueError) as e:
                self._log_error('STK_PUSH', f"Error initiating STK push: {str(e)}", payment_id)
                return None
            
        except (requests.exceptions.RequestException, ValueError) as e:
            self._log_error('STK_PUSH', f"Error initiating STK push: {str(e)}", payment_id)
            return None

    def verify_transaction(self, checkout_request_id: str) -> Optional[Dict[str, Any]]:
        """Query transaction status from Safaricom API"""
        access_token = self.get_access_token()
        if not access_token:
            return None

        if not self.validate_shortcode():
            return None

        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        password = self.generate_password(timestamp)

        payload = {
            "BusinessShortCode": self.business_shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "CheckoutRequestID": checkout_request_id
        }

        headers = self._bearer_headers(access_token)

        try:
            self._log_debug('QUERY', f"Verifying transaction: {checkout_request_id}")
            self._log_debug('QUERY', f"Query URL: {self.query_url}")
            self._log_debug('QUERY', f"Headers: {self._mask_headers(headers)}")
            response = self._perform_daraja_request(
                'post',
                self.query_url,
                headers=headers,
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            
            # Check if response is JSON before parsing
            try:
                result = response.json()
                self._log_debug('QUERY', f"Transaction verification result: {result.get('ResultCode')}")
                return result
            except ValueError as e:
                # Handle JSON parsing errors (e.g., HTML responses)
                self._log_error('QUERY', f"Failed to parse response as JSON: {str(e)}")
                self._log_error('QUERY', f"Response content type: {response.headers.get('content-type', 'unknown')}")
                self._log_error('QUERY', f"Response text (first 200 chars): {response.text[:200]}")
                # Return error result for HTML responses
                return {
                    'ResultCode': 1,
                    'ResultDesc': 'Failed to parse API response'
                }
            except requests.exceptions.RequestException as e:
                self._log_error('QUERY', f"Error verifying transaction: {str(e)}")
                return None
            
        except requests.exceptions.RequestException as e:
            self._log_error('QUERY', f"Error verifying transaction: {str(e)}")
            return None

    def validate_callback_data(self, callback_data: Dict[str, Any]) -> bool:
        """Validate M-Pesa callback data structure"""
        try:
            # Check if the required fields exist in the callback
            callback = callback_data.get('Body', {}).get('stkCallback', {})
            required_fields = ['CheckoutRequestID', 'ResultCode']
            
            if not all(field in callback for field in required_fields):
                return False
                
            # Validate ResultCode format
            result_code = callback.get('ResultCode')
            if result_code is None:
                return False
                
            result_code_str = str(result_code).strip()
            # Only successful callbacks must include metadata
            if result_code_str == self.SUCCESS and 'CallbackMetadata' not in callback:
                return False
                
            # Structural validation for the callback payload
            if not self._validate_callback_structure(callback_data):
                self._log_warning('CALLBACK', 'M-PESA callback structure validation failed')
                return False
                
            return True
            
        except (TypeError, ValueError, AttributeError) as e:
            self._log_error('CALLBACK', f"Error validating callback: {str(e)}")
            return False

    def _validate_callback_structure(self, callback_data: Dict[str, Any]) -> bool:
        """Validate the structure of incoming M-PESA callback payloads."""
        try:
            # Basic structural checks for the expected Daraja callback format
            callback = callback_data.get('Body', {}).get('stkCallback', {})
            
            if not isinstance(callback, dict):
                return False
                
            checkout_request_id = callback.get('CheckoutRequestID', '')
            if not checkout_request_id or len(checkout_request_id) > 100:
                return False
                
            metadata = callback.get('CallbackMetadata', {})
            if isinstance(metadata, dict):
                items = metadata.get('Item', [])
                if isinstance(items, list):
                    for item in items:
                        if not isinstance(item, dict):
                            return False
                        name = item.get('Name', '')
                        value = item.get('Value', '')
                        
                        if name == 'Amount':
                            try:
                                float(value)
                            except (ValueError, TypeError):
                                return False
                        elif name == 'PhoneNumber':
                            if not str(value).isdigit() or len(str(value)) < 9:
                                return False
            
            return True
            
        except (TypeError, ValueError, AttributeError) as e:
            self._log_error('CALLBACK', f"Error validating callback structure: {str(e)}")
            return False

    def extract_payment_details(self, callback_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract payment details from callback data"""
        try:
            callback = callback_data.get('Body', {}).get('stkCallback', {})
            result_code = str(callback.get('ResultCode', '1'))
            
            # Only extract details for successful payments
            if result_code != '0':
                return None
                
            metadata = {}
            for item in callback.get('CallbackMetadata', {}).get('Item', []):
                if 'Name' in item and 'Value' in item:
                    metadata[item['Name']] = item['Value']
            
            return {
                'transaction_id': metadata.get('MpesaReceiptNumber'),
                'amount': metadata.get('Amount'),
                'phone_number': callback.get('PhoneNumber', '')[-9:] if isinstance(callback.get('PhoneNumber', ''), str) else '',
                'checkout_request_id': callback.get('CheckoutRequestID'),
                'result_code': result_code,
                'result_desc': callback.get('ResultDesc', 'Success')
            }
            
        except (TypeError, ValueError, AttributeError) as e:
            self._log_error('CALLBACK', f"Error extracting payment details: {str(e)}")
            return None

    def is_configured(self) -> bool:
        """Check if M-PESA service is properly configured"""
        required_vars = [
            self.consumer_key,
            self.consumer_secret,
            self.passkey,
            self.business_shortcode
        ]
        required_urls = [
            self.oauth_url,
            self.stkpush_url,
            self.query_url,
            self.callback_url
        ]

        return len(self._get_configuration_issues()) == 0

    def is_payment_cancelled(self, result_code: str, result_desc: str) -> bool:
        """
        Check if payment was cancelled by the user.
        M-PESA returns specific result codes and descriptions for cancellations.
        """
        result_code_str = str(result_code).strip()
        result_desc_str = str(result_desc).lower().strip() if result_desc else ''

        # Result code 1 with cancel-related description indicates user cancelled
        # Common M-PESA cancellation responses:
        # - Code '1' with "user cancelled" or "cancelled" in description
        # - Code '1032' indicates the customer cancelled/rejected the STK request
        # - Code '20004' indicates the customer cancelled the transaction
        cancellation_keywords = ['cancel', 'cancelled', 'user cancel', 'declined', 'rejected']

        if result_code_str == self.INSUFFICIENT_FUNDS:
            return any(keyword in result_desc_str for keyword in cancellation_keywords)

        # A generic code '1' with an explicit cancellation description is
        # treated as cancelled (mirrors the generic code '1' handling for
        # timeouts in :meth:`is_payment_timed_out`). Descriptions that name a
        # rejection are surfaced as a separate REJECTED state by
        # :meth:`is_payment_rejected`.
        if result_code_str == '1' and any(
                keyword in result_desc_str
                for keyword in ('cancel', 'cancelled', 'user cancel')):
            return True

        if self.USER_CANCELLED in result_code_str:
            return True

        if result_code_str == self.INVALID_PIN and 'cancel' in result_desc_str:
            return True

        if '20004' in result_code_str:
            return True

        return False

    def is_payment_timed_out(self, result_code: str, result_desc: str) -> bool:
        """
        Check if the payment request timed out (result code 1037) or was
        reported with a timeout description while no decision was reached.

        NOTE: a timed-out transaction may still complete later at Safaricom.
        Callers must keep the payment reconcilable after marking it timed out.
        """
        result_code_str = str(result_code).strip()
        result_desc_str = str(result_desc).lower().strip() if result_desc else ''

        if self.TIMEOUT in result_code_str:
            return True

        # A generic code '1' with an explicit timeout description is treated as
        # a timeout rather than a plain failure so the UI can offer reconciliation.
        if result_code_str == '1' and any(k in result_desc_str for k in ('timeout', 'timed out', 'expired')):
            return True

        return False

    def is_payment_rejected(self, result_code: str, result_desc: str) -> bool:
        """
        Check if the payment was explicitly REJECTED (result code 2001 or 1014 -
        wrong PIN / invalid initiator credentials), i.e. the STK request was
        refused at M-PESA rather than actively cancelled by the user (1032) or
        timed out (1037).

        Distinct from :meth:`is_payment_cancelled` and :meth:`is_payment_timed_out`
        so the UI can show a clear, separate REJECTED state.
        """
        result_code_str = str(result_code).strip()
        result_desc_str = str(result_desc).lower().strip() if result_desc else ''

        if self.REJECTED in result_code_str or self.INVALID_PIN in result_code_str:
            return True

        # A generic code '1' with an explicit rejection description is treated as
        # rejected rather than a plain failure.
        if result_code_str == '1' and any(k in result_desc_str for k in ('rejected', 'declined', 'not authorised', 'not authorized')):
            return True

        return False

    def _find_known_result_code(self, result_code_str: str) -> Optional[str]:
        """Match the result code string against known Daraja result codes."""
        normalized = str(result_code_str or '').strip()
        if not normalized:
            return None

        if normalized in self.RESULT_CODE_MESSAGES:
            return normalized

        for known_code in sorted(self.RESULT_CODE_MESSAGES.keys(), key=len, reverse=True):
            if known_code == self.INSUFFICIENT_FUNDS:
                continue
            if known_code in normalized:
                return known_code

        return None

    def get_payment_state(self, result_code: str, result_desc: str) -> tuple:
        """
        Resolve the authoritative payment state from a Daraja result.

        Returns a ``(state, message)`` tuple where state is one of:
        ``completed``, ``cancelled``, ``timeout``, ``rejected``, ``failed``.

        This is the single source of truth for interpreting M-PESA results so
        the callback handler, status polling and any reconciliation path all
        reach the same conclusion for the same result code.
        """
        result_code_str = str(result_code).strip()
        matched_code = self._find_known_result_code(result_code_str)

        if matched_code == self.SUCCESS:
            return ('completed', self.RESULT_CODE_MESSAGES[self.SUCCESS])

        if self.is_payment_rejected(result_code_str, result_desc):
            return ('rejected', 'Payment was rejected; please verify your PIN and try again')

        if self.is_payment_cancelled(result_code_str, result_desc):
            return ('cancelled', 'Payment cancelled by user')

        if self.is_payment_timed_out(result_code_str, result_desc):
            return ('timeout', 'Payment request timed out. Please try again.')

        message = self.RESULT_CODE_MESSAGES.get(matched_code)
        if message:
            return ('failed', message)

        return ('failed', result_desc or 'Payment failed')

    def get_user_friendly_status(self, result_code: str, result_desc: str) -> tuple:
        """
        Get user-friendly status and message for payment result.
        Returns: (status, message) tuple

        Backward-compatible wrapper around :meth:`get_payment_state`; the
        ``timeout`` state is reported as ``failed`` for callers that predate
        the explicit timeout state.
        """
        state, message = self.get_payment_state(result_code, result_desc)
        if state == 'timeout':
            return ('failed', message)
        return (state, message)

