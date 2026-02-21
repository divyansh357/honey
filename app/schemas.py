"""
Pydantic Schema Definitions
============================
Defines request/response models for the Honeypot API.

IncomingRequest: Accepts evaluator requests with flexible field types
                 (Optional[Any]) to handle varying evaluator formats.
AgentReply:      Standard response with status and reply text.

Note: Fields use Optional[Any] intentionally — the evaluator sends
different formats across test scenarios, and strict typing would
cause 422 validation errors.

Updated for Feb 19 scoring rubric — includes all required and
optional fields for maximum response structure points.
"""

from pydantic import BaseModel, Field
from typing import Any, Optional, List, Dict, Union


class Message(BaseModel):
    """Individual message in conversation."""
    sender: str = Field(description="Message sender: 'scammer' or 'user'")
    text: str = Field(description="Message content text")
    timestamp: Optional[Union[int, str]] = Field(default=None, description="Unix timestamp or ISO string")


class Metadata(BaseModel):
    """Optional metadata about the conversation channel."""
    channel: Optional[str] = Field(default=None, description="Communication channel (sms, email, etc.)")
    language: Optional[str] = Field(default=None, description="Language code (en, hi, etc.)")
    locale: Optional[str] = Field(default=None, description="Locale identifier")


class IncomingRequest(BaseModel):
    """
    Incoming request from the GUVI evaluator.

    Uses Optional[Any] for maximum compatibility — the evaluator
    may send messages as dicts, strings, or other formats depending
    on the test scenario.
    """
    sessionId: Optional[str] = Field(default=None, description="Unique session identifier")
    message: Optional[Any] = Field(default=None, description="Current scammer message (dict or string)")
    conversationHistory: Optional[Any] = Field(default=None, description="Previous messages as list of dicts")
    metadata: Optional[Any] = Field(default=None, description="Channel/language metadata")
    callbackUrl: Optional[str] = Field(default=None, description="Override GUVI callback URL")
    isLastTurn: Optional[bool] = Field(default=None, description="Set true on final turn to finalize")


class EngagementMetrics(BaseModel):
    """Metrics tracking honeypot engagement quality."""
    engagementDurationSeconds: int = Field(description="Total engagement duration in seconds")
    totalMessagesExchanged: int = Field(description="Total messages in conversation")


class ExtractedIntelligence(BaseModel):
    """
    Intelligence extracted from scammer messages.

    Includes all data types from Feb 19 evaluation spec:
    phones, bank accounts, UPI IDs, links, emails, case IDs,
    policy numbers, and order numbers.
    """
    phoneNumbers: List[str] = Field(default=[], description="Phone numbers found")
    bankAccounts: List[str] = Field(default=[], description="Bank account numbers found")
    upiIds: List[str] = Field(default=[], description="UPI IDs found")
    phishingLinks: List[str] = Field(default=[], description="Suspicious URLs found")
    emailAddresses: List[str] = Field(default=[], description="Email addresses found")
    suspiciousKeywords: List[str] = Field(default=[], description="Scam indicator keywords found")
    caseIds: List[str] = Field(default=[], description="Case/reference IDs found")
    policyNumbers: List[str] = Field(default=[], description="Policy numbers found")
    orderNumbers: List[str] = Field(default=[], description="Order/transaction IDs found")


class AgentReply(BaseModel):
    """Response returned to the evaluator."""
    status: str = Field(description="Always 'success' for evaluator compatibility")
    reply: str = Field(description="Agent's conversational reply to the scammer")