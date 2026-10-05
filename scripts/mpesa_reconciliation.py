"""
M-PESA STK Push Query reconciliation.

The Safaricom callback is the primary completion signal, but it can be
delayed, lost, or never delivered. This module provides the authoritative
fallback:

* ``reconcile_expired_payment`` runs one STK Push Query for a single expired
  in-flight payment and feeds the result through the same state-machine + 
  fulfilment path as the callback (no separate success logic).
* ``sweep_expired_payments`` finds every expired in-flight M-PESA payment and
  reconciles it, so a payment completes (and unlocks the product/subscription)
  server-side even when the customer closed the browser.
* ``start_reconciliation_worker`` runs the sweep on a background daemon thread,
  which also survives application/container restarts: on boot the worker picks
  up any payments that were still in flight when the process stopped.

Both the callback handler and this query path call the same
``_finalize_successful_mpesa_payment`` fulfilment, and every transition is
logged with a structured ``[M-PESA][PAYMENT]`` line (see the model's
``_transition`` helper).
"""
import logging
import os
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)

# Process-wide lock so the background sweeper and the status-polling routes
# never issue two Daraja STK Push Queries for the same payment at the same
# time. Fulfilment is idempotent regardless (unique order_id / Payment intent
# keys), so this lock only avoids duplicate network queries.
_RECONCILE_LOCK = threading.Lock()

_worker_started = False

# A payment that returns a "still processing" answer (500.001.1001) stays in
# the reconciling state and is re-queried on later sweeps, but never forever:
# after this many attempts without a definitive result it is terminalized to
# the safe user-visible "timeout" state (a genuine late callback with a receipt
# can still upgrade it to completed).
_MAX_QUERY_ATTEMPTS = 5


def reconcile_expired_payment(payment):
    """Reconcile one expired in-flight payment via the STK Push Query API.

    Serialized process-wide. Re-checks under the lock because another caller
    (callback, status poll, or the sweep itself) may have just terminalised the
    payment.

    Preserves the existing contract: a payment whose query returns no
    definitive ``ResultCode`` (network error / Daraja unavailable) is marked
    ``timeout`` -- a safe, terminal, user-facing state -- and a late legitimate
    callback can still upgrade it to ``completed``.

    SECURITY BARRIER: Daraja's STK Push Query reports ``ResultCode`` "0" /
    "The service request is processed successfully." for requests that never
    actually settled (prompt left unanswered / timed out). A bare "0" is NOT
    proof of payment. Completion is only trusted when the query response
    carries a real ``MpesaReceiptNumber`` inside ``CallbackMetadata``; anything
    less is treated as non-definitive (``timeout``), never ``completed``.

    A query that reports the transaction is STILL IN FLIGHT (``errorCode``
    ``500.001.1001``) does not terminalize the payment: it stays ``reconciling``
    so a later sweep re-queries. Retries are bounded by ``_MAX_QUERY_ATTEMPTS``
    per payment, so this can never loop forever; once the budget is exhausted
    the payment lands in the safe ``timeout`` state.
    """
    with _RECONCILE_LOCK:
        if not payment.is_expired:
            return

        verification = dict(payment.verification_data or {})
        attempts = int(verification.get('query_attempts', 0) or 0)

        from ..models import db

        if attempts >= _MAX_QUERY_ATTEMPTS:
            # Retry budget exhausted without a definitive answer: never loop
            # forever. Terminalize to the safe timeout so the UI shows a final
            # state; a genuine late callback (with a receipt) still upgrades it.
            payment.mark_timeout(
                result_desc='Payment could not be confirmed after several checks. '
                            'If you completed the payment, it will be confirmed shortly.',
                source='TIMEOUT')
            db.session.commit()
            return

        from .mpesa_service import MpesaService
        from ..user.routes.mpesa import _finalize_successful_mpesa_payment

        try:
            # Surface the reconciling state so the frontend shows
            # "Payment is still being confirmed" while the query is in flight
            # (and so a crash mid-query leaves a state the sweep retries).
            payment.mark_reconciling(source='QUERY')
            db.session.commit()

            service = MpesaService()
            result = service.verify_transaction(payment.checkout_request_id)

            # Consume the retry budget exactly once per query regardless of the
            # response, so a series of "still processing" answers cannot spin
            # forever (guard above).
            verification['query_attempts'] = attempts + 1
            verification['status_query_at'] = datetime.utcnow().isoformat()
            payment.verification_data = verification

            # Transaction still in flight at Safaricom (request accepted, no
            # definitive result yet): do NOT terminalize, do NOT mark failed, do
            # NOT fulfil. Leave the payment reconciling; the next sweep re-queries,
            # bounded by the attempt budget above. Checked before ResultCode
            # because a 500.001.1001 response can also carry a ResultCode.
            if isinstance(result, dict) and result.get('errorCode') == '500.001.1001':
                db.session.commit()
                return

            if result and result.get('ResultCode') is not None:
                result_code = result.get('ResultCode')
                result_desc = result.get('ResultDesc', '')
                state, message = service.get_payment_state(str(result_code), result_desc)

                if state == 'completed':
                    # SECURITY BARRIER: a query "ResultCode 0" merely means the
                    # request was processed by Daraja, NOT that the customer
                    # paid. Safaricom's STK Push Query returns "0" /
                    # "processed successfully" for in-flight or timed-out
                    # requests too, and it does not return CallbackMetadata.
                    # Only a genuine MpesaReceiptNumber proves settlement; a
                    # query that reports success without one must never mark the
                    # payment completed and must never fulfil (unlock) the
                    # product. The genuine callback (which always carries the
                    # receipt) can still upgrade this to completed later.
                    receipt = _query_receipt_number(result)
                    if receipt:
                        payment.mark_completed(
                            mpesa_receipt_number=receipt, result_desc=message, source='QUERY')
                        db.session.commit()
                        # Idempotent: only fulfils once even if the callback also
                        # reports this payment as completed.
                        _finalize_successful_mpesa_payment(payment)
                        return

                    payment.mark_timeout(
                        result_code=result_code,
                        result_desc='Payment could not be confirmed. If you completed the payment, it will be confirmed shortly.',
                        source='QUERY')
                    db.session.commit()
                    return

                if state == 'cancelled':
                    payment.mark_cancelled(
                        result_code=result_code, result_desc=result_desc or message, source='QUERY')
                elif state == 'rejected':
                    payment.mark_rejected(
                        result_code=result_code, result_desc=result_desc or message, source='QUERY')
                elif state == 'timeout':
                    payment.mark_timeout(
                        result_code=result_code, result_desc=result_desc or message, source='QUERY')
                else:
                    # Query surfaced a failure state. Only recognise codes Daraja
                    # actually defines as terminal refusals; anything else (e.g.
                    # 4999 = still in flight, 500.001.1001 = being processed,
                    # generic network/proxy blips) must NOT be a one-way failure.
                    # Surface the safe "timeout" state so a genuine completion via
                    # a late callback (or a later query) is not foreclosed. Uses
                    # getattr so stubbed services (tests) default to safe.
                    known_matcher = getattr(service, '_find_known_result_code', None)
                    is_known_terminal = (
                        str(result_code) == '1'
                        or (known_matcher and known_matcher(str(result_code)))
                    )
                    if is_known_terminal:
                        payment.mark_failed(
                            result_code=result_code, result_desc=result_desc or message, source='QUERY')
                    else:
                        payment.mark_timeout(
                            result_code=result_code,
                            result_desc='Payment is still being confirmed. Please check again shortly.',
                            source='QUERY')
                db.session.commit()
                return

            # Query unavailable / no definitive answer: surface timeout. A late
            # legitimate callback still reconciles this payment to completed via
            # the callback handler.
            payment.mark_timeout(
                result_desc='Payment request timed out. If you completed the payment, it will be confirmed shortly.',
                source='TIMEOUT')
            db.session.commit()
        except Exception as e:
            logger.error(
                'M-PESA reconciliation query error for %s: %s',
                payment.transaction_reference, e)
            try:
                db.session.rollback()
            except Exception:
                pass


def _query_receipt_number(result, fallback=None):
    """Extract the M-PESA receipt number from an STK Push Query response.

    Daraja returns the receipt inside ``CallbackMetadata.Item`` (Name =
    ``MpesaReceiptNumber``), the same shape as a callback. The top-level
    ``MpesaReceiptNumber`` key is not populated by the query endpoint.
    """
    if not isinstance(result, dict):
        return fallback
    try:
        metadata = result.get('CallbackMetadata') or {}
        for item in (metadata.get('Item') or []):
            if isinstance(item, dict) and item.get('Name') == 'MpesaReceiptNumber':
                return item.get('Value') or fallback
    except (AttributeError, TypeError):
        pass
    return result.get('MpesaReceiptNumber') or fallback


def sweep_expired_payments(app):
    """Reconcile every expired in-flight M-PESA payment.

    ``pending`` / ``processing`` / ``reconciling`` payments whose expiry has
    passed are queried once each and moved to a definitive state (or, when
    Daraja is unavailable, to ``timeout`` which a late callback can upgrade).
    """
    from ..models import db, MpesaPayment

    batch_size = int(app.config.get('MPESA_RECONCILE_BATCH_SIZE', 50) or 50)
    with app.app_context():
        expired = (
            MpesaPayment.query
            .filter(
                MpesaPayment.status.in_(('pending', 'processing', 'reconciling')),
                MpesaPayment.expires_at.isnot(None),
                MpesaPayment.expires_at <= datetime.utcnow(),
            )
            .order_by(MpesaPayment.expires_at.asc())
            .limit(batch_size)
            .all()
        )
        for payment in expired:
            try:
                reconcile_expired_payment(payment)
            except Exception as e:
                logger.error(
                    'M-PESA sweep failed for %s: %s',
                    payment.transaction_reference, e)
        # Release the request-bound session so the long-lived worker thread never
        # leaks a session/transaction across sweeps.
        try:
            db.session.remove()
        except Exception:
            pass


def _worker_loop(app):
    interval = int(app.config.get('MPESA_RECONCILE_INTERVAL_SECONDS', 60) or 60)
    while True:
        try:
            sweep_expired_payments(app)
        except Exception:
            logger.exception('M-PESA reconciliation sweep failed')
        time.sleep(interval)


def start_reconciliation_worker(app):
    """Start the single background M-PESA reconciliation worker (daemon).

    Returns True if a new worker was started, False if one already exists or
    the feature is disabled via ``DISABLE_MPESA_RECONCILIATION``. The caller
    (``create_app``) decides the monitor-owner gating via
    ``should_run_background_monitors()``.
    """
    global _worker_started
    if _worker_started:
        return False

    disable = os.environ.get('DISABLE_MPESA_RECONCILIATION', '').strip().lower()
    if disable in ('1', 'true', 'yes', 'on'):
        app.logger.info('M-PESA reconciliation worker disabled by configuration')
        return False

    thread = threading.Thread(
        target=_worker_loop,
        args=(app,),
        name='mpesa-reconciliation-worker',
        daemon=True,
    )
    thread.start()
    _worker_started = True
    return True