"""
Purchase Email Service
Handles sending email notifications for purchases to both buyers and admin
"""

import html
import os
import time
from datetime import datetime
from flask import current_app
import logging

from monetization.email_system.core.email_queue import email_queue
from monetization.email_system.core.email_service import EmailService as CoreEmailService
from monetization.email_system.core.templates.config import get_brand_context, render_template, mark_safe

logger = logging.getLogger(__name__)

class PurchaseEmailService:
    """Service for handling purchase-related email notifications"""

    @staticmethod
    def get_email_config():
        """Get SMTP configuration from app config or environment."""
        # SMTP transport config comes from the standard MAIL_*/SMTP_* config and
        # env vars regardless of any "method" flag (the Gmail-specific path was
        # removed 2026-08-05 so the centralized system never depends on
        # GMAIL_SMTP_*).
        server = current_app.config.get('SMTP_SERVER') or os.getenv('SMTP_SERVER') or current_app.config.get('MAIL_SERVER') or os.getenv('MAIL_SERVER') or ''
        port = int(current_app.config.get('MAIL_PORT') or os.getenv('SMTP_PORT') or 587)
        username = (current_app.config.get('MAIL_USERNAME')
                or current_app.config.get('SMTP_USERNAME')
                or os.getenv('MAIL_USERNAME')
                or os.getenv('SMTP_USERNAME') or '').strip()
        password = (current_app.config.get('MAIL_PASSWORD')
                or current_app.config.get('SMTP_PASSWORD')
                or os.getenv('MAIL_PASSWORD')
                or os.getenv('SMTP_PASSWORD') or '').strip()
        use_tls = str(current_app.config.get('MAIL_USE_TLS') or os.getenv('SMTP_USE_TLS') or 'true').lower() in {'1', 'true', 'yes', 'on'}

        return {
            'server': server,
            'port': port,
            'username': username,
            'password': password,
            'use_tls': use_tls,
            'from_email': (current_app.config.get('MAIL_DEFAULT_SENDER') or current_app.config.get('EMAIL_FROM') or current_app.config.get('SMTP_USERNAME') or os.getenv('MAIL_DEFAULT_SENDER') or os.getenv('EMAIL_FROM') or os.getenv('SMTP_USERNAME') or '').strip(),
            'default_sender': (current_app.config.get('MAIL_DEFAULT_SENDER') or current_app.config.get('EMAIL_FROM') or current_app.config.get('SMTP_USERNAME') or os.getenv('MAIL_DEFAULT_SENDER') or os.getenv('EMAIL_FROM') or os.getenv('SMTP_USERNAME') or '').strip(),
            'from_name': (current_app.config.get('MAIL_FROM_NAME') or current_app.config.get('FROM_NAME') or 'Odivora').strip(),
            'admin_email': (current_app.config.get('ADMIN_EMAIL') or 'support@odivora.com').strip(),
            'support_email': (current_app.config.get('SUPPORT_EMAIL') or 'support@yourdomain.com').strip(),
        }

    @staticmethod
    def is_email_configured():
        """Check if email is properly configured"""
        config = PurchaseEmailService.get_email_config()
        return bool(config['username'] and config['password'] and config['from_email'])

    @staticmethod
    def _build_download_links_html(download_links):
        parts = []
        for link in download_links:
            product_name = html.escape(str(link.get('product_name') or 'Product'))
            expires_at = link.get('expires_at')
            if expires_at:
                expires_text = expires_at.strftime('%B %d, %Y at %I:%M %p')
            else:
                expires_text = 'No expiry (Lifetime Access)'

            parts.append(f"""
                <div style=\"margin: 10px 0; padding: 14px; background: #f8fafc; border-radius: 10px; border-left: 4px solid #2563eb;\">
                    <p style=\"margin: 0 0 4px;\"><strong>{product_name}</strong></p>
                    <p style=\"margin: 0; font-size: 13px; color: #475569;\">Available until: {expires_text}</p>
                </div>
            """)
        return mark_safe('\n'.join(parts))

    @staticmethod
    def _build_order_summary_rows_html(purchase_details):
        rows = []
        for product in purchase_details:
            symbol = product.get('currency_symbol', 'KSh')
            amount = float(product.get('amount') or 0)
            product_name = html.escape(str(product.get('product_name', '')))
            rows.append(f"""
                <tr>
                    <td style=\"padding: 10px; border-bottom: 1px solid #dee2e6;\">{product_name}</td>
                    <td style=\"padding: 10px; text-align: right; border-bottom: 1px solid #dee2e6;\">{symbol}{amount:.2f}</td>
                </tr>
            """)
        return mark_safe('\n'.join(rows))

    @staticmethod
    def _build_products_html(purchase_details):
        rows = []
        for product in purchase_details:
            symbol = product.get('currency_symbol', 'KSh')
            amount = float(product.get('amount') or 0)
            product_name = html.escape(str(product.get('product_name', '')))
            rows.append(f"""
                <tr>
                    <td style=\"padding: 12px; border: 1px solid #ddd;\">{product_name}</td>
                    <td style=\"padding: 12px; border: 1px solid #ddd; text-align: right;\">{symbol}{amount:.2f}</td>
                </tr>
            """)
        return mark_safe('\n'.join(rows))

    @staticmethod
    def _render_template(template_name, context):
        brand_context = get_brand_context(context.get('user_name'))
        return render_template(template_name, {**brand_context, **context})

    @staticmethod
    def _send_email(to_email, subject, html_content, mail_type=None, sender_profile=None):
        config = PurchaseEmailService.get_email_config()
        email_service = CoreEmailService(config=config)
        try:
            success = email_service.send_message(
                to_email=to_email,
                subject=subject,
                html_content=html_content,
                mail_type=mail_type,
                sender_profile=sender_profile,
            )
            if success:
                logger.info(f"Email sent successfully to {to_email}")
            else:
                logger.warning(f"Email service returned failure for {to_email}")
            return success
        except Exception as exc:
            logger.error(f"Failed to send email to {to_email}: {exc}", exc_info=True)
            return False

    @staticmethod
    def send_purchase_confirmation_to_buyer(user_email, user_name, purchase_details, download_links, total_amount, currency='KES'):
        """
        Send purchase confirmation email to the buyer

        Args:
            user_email (str): Buyer's email address
            user_name (str): Buyer's name
            purchase_details (list): List of purchased products
            download_links (list): List of download links
            total_amount (float): Total purchase amount
            currency (str): Currency code (KES or USD)

        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            if not PurchaseEmailService.is_email_configured():
                logger.error('Email credentials not properly configured')
                return False

            logger.info(f'Preparing purchase confirmation email for buyer: {user_email}')

            currency_symbol = 'KSh' if currency == 'KES' else '$'
            download_links_html = PurchaseEmailService._build_download_links_html(download_links)
            order_summary_rows = PurchaseEmailService._build_order_summary_rows_html(purchase_details)

            subject = 'Your Purchase is Complete - Products Available in Your Account'
            html_content = PurchaseEmailService._render_template(
                'purchase_buyer_notification.html',
                {
                    'subject': subject,
                    'user_name': user_name,
                    'download_links_html': download_links_html,
                    'order_summary_rows': order_summary_rows,
                    'total_amount': f'{currency_symbol}{total_amount:.2f}',
                    'message': 'If you have any questions about your purchase, simply reply to this email and our support team will be happy to assist.',
                },
            )

            if PurchaseEmailService._send_email(user_email, subject, html_content, mail_type='PURCHASE_CONFIRMATION', sender_profile='BILLING'):
                logger.info(f'Purchase confirmation email sent successfully to {user_email}')
                return True
            return False
        except Exception as e:
            logger.error(f'Failed to send purchase confirmation email to {user_email}: {str(e)}', exc_info=True)
            return False

    @staticmethod
    def send_purchase_alert_to_admin(user_email, user_name, purchase_details, total_amount, currency='KES'):
        """
        Send purchase alert email to admin

        Args:
            user_email (str): Buyer's email address
            user_name (str): Buyer's name
            purchase_details (list): List of purchased products
            total_amount (float): Total purchase amount

        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            if not PurchaseEmailService.is_email_configured():
                logger.error('Email credentials not properly configured')
                return False

            config = PurchaseEmailService.get_email_config()
            logger.info(f'Preparing purchase alert email for admin about user: {user_email}')

            currency_symbol = 'KSh' if currency == 'KES' else '$'
            products_html = PurchaseEmailService._build_products_html(purchase_details)
            order_date = datetime.now().strftime('%B %d, %Y at %I:%M %p')
            subject = f'New Purchase Alert - {user_name} just made a purchase!'

            html_content = PurchaseEmailService._render_template(
                'purchase_admin_alert.html',
                {
                    'subject': subject,
                    'user_name': user_name,
                    'user_email': user_email,
                    'total_amount': f'{currency_symbol}{total_amount:.2f}',
                    'order_date': order_date,
                    'products_html': products_html,
                    'message': 'This notification was generated automatically for the admin team.',
                },
            )

            if PurchaseEmailService._send_email(config['admin_email'], subject, html_content, mail_type='PURCHASE_CONFIRMATION', sender_profile='ADMIN'):
                logger.info(f'Purchase alert email sent successfully to admin {config["admin_email"]} about user {user_email}')
                return True
            return False
        except Exception as e:
            logger.error(f'Failed to send purchase alert email to admin: {str(e)}', exc_info=True)
            return False

    @staticmethod
    def send_review_notification_to_buyer(user_email, user_name, product_name, review_title, review_comment, rating):
        """Send a confirmation email to the buyer after a review is submitted."""
        try:
            if not PurchaseEmailService.is_email_configured():
                logger.error('Email credentials not properly configured for review notification')
                return False

            subject = f'✅ Your review for {product_name} was received'
            rating_text = '★' * rating + '☆' * (5 - rating)
            html_content = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #111827;">Thanks for your review</h2>
                <p>Hello {user_name},</p>
                <p>Your review for <strong>{product_name}</strong> has been received and is now live on our product page.</p>
                <div style="background: #f8fafc; padding: 16px; border-radius: 8px; margin: 16px 0;">
                    <p style="margin: 0 0 8px;"><strong>Rating:</strong> {rating_text}</p>
                    <p style="margin: 0 0 8px;"><strong>Title:</strong> {review_title or 'No title provided'}</p>
                    <p style="margin: 0;">{review_comment or 'No comment provided'}</p>
                </div>
                <p>We appreciate your feedback and it helps other customers make confident decisions.</p>
            </div>
            """
            return PurchaseEmailService._send_email(user_email, subject, html_content, mail_type='PRODUCT_REVIEW_CONFIRMATION', sender_profile='DEFAULT')
        except Exception as e:
            logger.error(f'Failed to send review confirmation email to {user_email}: {str(e)}', exc_info=True)
            return False

    @staticmethod
    def send_review_alert_to_admin(user_email, user_name, product_name, review_title, review_comment, rating):
        """Send an admin alert when a buyer leaves a product review."""
        try:
            if not PurchaseEmailService.is_email_configured():
                logger.error('Email credentials not properly configured for admin review alert')
                return False

            config = PurchaseEmailService.get_email_config()
            subject = f'📝 New product review for {product_name}'
            rating_text = '★' * rating + '☆' * (5 - rating)
            html_content = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #111827;">New Product Review</h2>
                <p>A new review was posted by <strong>{user_name}</strong> ({user_email}).</p>
                <p><strong>Product:</strong> {product_name}</p>
                <p><strong>Rating:</strong> {rating_text}</p>
                <p><strong>Title:</strong> {review_title or 'No title provided'}</p>
                <p><strong>Comment:</strong> {review_comment or 'No comment provided'}</p>
            </div>
            """
            return PurchaseEmailService._send_email(config['admin_email'], subject, html_content, mail_type='PRODUCT_REVIEW_ALERT', sender_profile='ADMIN')
        except Exception as e:
            logger.error(f'Failed to send admin review alert for {product_name}: {str(e)}', exc_info=True)
            return False

    @staticmethod
    def send_review_notifications(user_email, user_name, product_name, review_title, review_comment, rating):
        """Send buyer and admin notifications for a new product review."""
        results = {
            'buyer_email_sent': False,
            'admin_email_sent': False,
            'errors': []
        }

        try:
            results['buyer_email_sent'] = PurchaseEmailService.send_review_notification_to_buyer(
                user_email=user_email,
                user_name=user_name,
                product_name=product_name,
                review_title=review_title,
                review_comment=review_comment,
                rating=rating,
            )
        except Exception as e:
            results['errors'].append(f'Buyer review email error: {str(e)}')

        try:
            results['admin_email_sent'] = PurchaseEmailService.send_review_alert_to_admin(
                user_email=user_email,
                user_name=user_name,
                product_name=product_name,
                review_title=review_title,
                review_comment=review_comment,
                rating=rating,
            )
        except Exception as e:
            results['errors'].append(f'Admin review email error: {str(e)}')

        return results

    @staticmethod
    def send_purchase_notifications(user_email, user_name, purchase_details, download_links, total_amount, currency='KES'):
        """
        Enqueue buyer and admin notification emails for async delivery.

        Emails are dispatched through the rate-limited :class:`EmailQueue`
        so that Zoho's per-account sending limits are respected without
        blocking the HTTP request path.

        Args:
            user_email (str): Buyer's email address
            user_name (str): Buyer's name
            purchase_details (list): List of purchased products
            download_links (list): List of download links
            total_amount (float): Total purchase amount
            currency (str): Currency code (KES or USD)

        Returns:
            dict: Results indicating whether each email was *queued*
        """
        results = {
            'buyer_email_queued': False,
            'admin_email_queued': False,
            'errors': []
        }

        # Add currency_symbol to each purchase detail
        currency_symbol = 'KSh' if currency == 'KES' else '$'
        for pd_item in purchase_details:
            pd_item['currency_symbol'] = currency_symbol

        # --- Enqueue buyer confirmation email ----------------------------
        try:
            if not PurchaseEmailService.is_email_configured():
                results['errors'].append('Email credentials not configured')
                return results

            buyer_html = PurchaseEmailService._render_buyer_email(
                user_email, user_name, purchase_details, download_links, total_amount, currency
            )
            buyer_subject = 'Your Purchase is Complete - Products Available in Your Account'

            email_queue.enqueue(
                to_email=user_email,
                subject=buyer_subject,
                html_content=buyer_html,
                mail_type='PURCHASE_CONFIRMATION',
                sender_profile='BILLING',
            )
            results['buyer_email_queued'] = True
            logger.info('Buyer confirmation email queued for %s', user_email)
        except Exception as e:
            results['errors'].append(f'Buyer email queue error: {str(e)}')

        # --- Enqueue admin alert email (sent after buyer, rate-limited) ---
        try:
            if not PurchaseEmailService.is_email_configured():
                results['errors'].append('Email credentials not configured')
                return results

            config = PurchaseEmailService.get_email_config()
            admin_html = PurchaseEmailService._render_admin_email(
                user_email, user_name, purchase_details, total_amount, currency
            )
            admin_subject = f'New Purchase Alert - {user_name} just made a purchase!'

            email_queue.enqueue(
                to_email=config['admin_email'],
                subject=admin_subject,
                html_content=admin_html,
                mail_type='PURCHASE_CONFIRMATION',
                sender_profile='ADMIN',
            )
            results['admin_email_queued'] = True
            logger.info('Admin alert email queued for %s about user %s', config['admin_email'], user_email)
        except Exception as e:
            results['errors'].append(f'Admin email queue error: {str(e)}')

        return results

    # ------------------------------------------------------------------
    # Private helpers for building email HTML (extracted for queue usage)
    # ------------------------------------------------------------------

    @staticmethod
    def _render_buyer_email(user_email, user_name, purchase_details, download_links, total_amount, currency='KES'):
        currency_symbol = 'KSh' if currency == 'KES' else '$'
        download_links_html = PurchaseEmailService._build_download_links_html(download_links)
        order_summary_rows = PurchaseEmailService._build_order_summary_rows_html(purchase_details)
        subject = 'Your Purchase is Complete - Products Available in Your Account'
        return PurchaseEmailService._render_template(
            'purchase_buyer_notification.html',
            {
                'subject': subject,
                'user_name': user_name,
                'download_links_html': download_links_html,
                'order_summary_rows': order_summary_rows,
                'total_amount': f'{currency_symbol}{total_amount:.2f}',
                'message': 'If you have any questions about your purchase, simply reply to this email and our support team will be happy to assist.',
            },
        )

    @staticmethod
    def _render_admin_email(user_email, user_name, purchase_details, total_amount, currency='KES'):
        currency_symbol = 'KSh' if currency == 'KES' else '$'
        products_html = PurchaseEmailService._build_products_html(purchase_details)
        order_date = datetime.now().strftime('%B %d, %Y at %I:%M %p')
        subject = f'New Purchase Alert - {user_name} just made a purchase!'
        config = PurchaseEmailService.get_email_config()
        return PurchaseEmailService._render_template(
            'purchase_admin_alert.html',
            {
                'subject': subject,
                'user_name': user_name,
                'user_email': user_email,
                'total_amount': f'{currency_symbol}{total_amount:.2f}',
                'order_date': order_date,
                'products_html': products_html,
                'message': 'This notification was generated automatically for the admin team.',
            },
        )
