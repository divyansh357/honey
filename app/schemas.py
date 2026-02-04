# app/schemas.py
from pydantic import BaseModel
from typing import Any, Optional, List, Dict, Union

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Optional[Union[int, str]] = None

class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

class IncomingRequest(BaseModel):
    sessionId: Optional[str] = None
    message: Optional[Any] = None
    conversationHistory: Optional[Any] = None
    metadata: Optional[Any] = None


class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int

class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []

# class ApiResponse(BaseModel):
#     status: str
#     scamDetected: bool
#     engagementMetrics: EngagementMetrics
#     extractedIntelligence: ExtractedIntelligence
#     agentNotes: str

class AgentReply(BaseModel):
    status: str
    reply: str