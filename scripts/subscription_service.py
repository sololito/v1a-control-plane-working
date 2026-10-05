"""
Unified subscription service for handling single tool and bundle upgrades.

This module provides centralized functions for managing subscriptions,
preventing duplicate entries, and ensuring consistent behavior across
all upgrade paths.
"""

from datetime import datetime, timedelta
from typing import Optional
from flask import current_app
from ..models import db, SingleToolSubscription, SubscriptionStatus


def activate_single_tool(user_id: int, tool_id: str, billing_cycle: str = 'monthly', 
                        paypal_subscription_id: Optional[str] = None) -> SingleToolSubscription:
    """
    Activate or renew a single tool subscription for a user.
    
    This function handles three scenarios:
    1. First-time single tool purchase
    2. Re-upgrade / renewal of the same single tool
    3. Bundle upgrade (when called in a loop)
    
    Args:
        user_id: The user ID
        tool_id: The tool identifier (e.g., 'tts', 'stt', etc.)
        billing_cycle: 'monthly' or 'yearly' or 'bundle'
        paypal_subscription_id: Optional PayPal subscription ID for tracking
        
    Returns:
        SingleToolSubscription: The created or updated subscription
        
    Raises:
        IntegrityError: If database constraints are violated
    """
    now = datetime.utcnow()
    
    # Calculate end date based on billing cycle
    if billing_cycle == 'yearly':
        end_date = now + timedelta(days=365)
    elif billing_cycle == 'bundle':
        end_date = now + timedelta(days=365)  # Bundle tools get yearly access
    else:  # monthly or default
        end_date = now + timedelta(days=30)
    
    # Use autoflush protection to prevent premature flushing
    with db.session.no_autoflush:
        # Check for existing subscription
        existing_sub = (
            db.session.query(SingleToolSubscription)
            .filter_by(user_id=user_id, tool_id=tool_id)
            .first()
        )
        
        if existing_sub:
            # Update existing subscription (renewal/upgrade)
            current_app.logger.info(f'Updating existing single tool subscription for {tool_id}, user {user_id}')
            existing_sub.status = SubscriptionStatus.ACTIVE
            existing_sub.billing_cycle = billing_cycle
            existing_sub.start_date = now
            existing_sub.end_date = end_date
            existing_sub.auto_renew = True
            existing_sub.paypal_subscription_id = paypal_subscription_id
            existing_sub.updated_at = now
            return existing_sub
        
        # Create new subscription (first-time purchase)
        current_app.logger.info(f'Creating new single tool subscription for {tool_id}, user {user_id}')
        new_sub = SingleToolSubscription(
            user_id=user_id,
            tool_id=tool_id,
            status=SubscriptionStatus.ACTIVE,
            billing_cycle=billing_cycle,
            start_date=now,
            end_date=end_date,
            auto_renew=True,
            paypal_subscription_id=paypal_subscription_id,
            created_at=now,
            updated_at=now,
        )
        db.session.add(new_sub)
        return new_sub


def check_paypal_subscription_processed(paypal_subscription_id: str) -> Optional[SingleToolSubscription]:
    """
    Check if a PayPal subscription has already been processed to prevent double-calls.
    
    Args:
        paypal_subscription_id: The PayPal subscription ID to check
        
    Returns:
        SingleToolSubscription or None: Existing subscription if found
    """
    if not paypal_subscription_id:
        return None
        
    return (
        db.session.query(SingleToolSubscription)
        .filter_by(paypal_subscription_id=paypal_subscription_id)
        .first()
    )


def activate_bundle_tools(user_id: int, bundle_tools: list, billing_cycle: str = 'bundle',
                         paypal_subscription_id: Optional[str] = None) -> list:
    """
    Activate multiple tools as part of a bundle upgrade.
    
    Args:
        user_id: The user ID
        bundle_tools: List of tool IDs to activate
        billing_cycle: Typically 'bundle'
        paypal_subscription_id: Optional PayPal subscription ID (will be None for individual tools)
        
    Returns:
        list: List of created/updated SingleToolSubscription objects
    """
    activated_tools = []
    
    for i, tool_id in enumerate(bundle_tools):
        try:
            # For bundle tools, we don't assign PayPal subscription ID to individual tools
            # to avoid UNIQUE constraint violations. The main bundle subscription handles payment.
            tool_paypal_id = None
            
            sub = activate_single_tool(
                user_id=user_id,
                tool_id=tool_id,
                billing_cycle=billing_cycle,
                paypal_subscription_id=tool_paypal_id
            )
            activated_tools.append(sub)
        except Exception as e:
            current_app.logger.error(f'Failed to activate tool {tool_id} for user {user_id}: {str(e)}')
            # Continue with other tools even if one fails
            continue
    
    return activated_tools
