from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base


class Case(Base):
    __tablename__ = "cases"

    id = Column(String, primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    threat_type = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    verdict = Column(String, nullable=False)
    is_demo = Column(Boolean, default=False)
    risk_score_total = Column(Integer, nullable=False)
    risk_score_level = Column(String, nullable=False)
    risk_score_confidence = Column(Float, nullable=False)
    risk_breakdown = Column(JSON)
    risk_explanation = Column(Text)
    why_flagged = Column(JSON)
    summary = Column(Text)
    mitre_mappings = Column(JSON)
    timeline = Column(JSON)
    graph_nodes = Column(JSON)
    graph_edges = Column(JSON)

    email = relationship("Email", back_populates="case", uselist=False, cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="case", cascade="all, delete-orphan")


class CaseIDSequence(Base):
    __tablename__ = "case_id_sequences"

    date_key = Column(String, primary_key=True)
    last_sequence = Column(Integer, nullable=False)


class Email(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), unique=True)
    from_addr = Column(String)
    to_addr = Column(String)
    subject = Column(String)
    date = Column(String)
    reply_to = Column(String)
    message_id = Column(String)
    body_text = Column(Text)
    received_ips = Column(JSON)
    received_path = Column(JSON)
    urls = Column(JSON)
    email_addresses = Column(JSON)
    headers = Column(JSON)
    attachments = Column(JSON)
    auth_spf = Column(String)
    auth_dkim = Column(String)
    auth_dmarc = Column(String)
    auth_summary = Column(Text)
    auth_spf_detail = Column(Text)
    auth_dkim_detail = Column(Text)
    auth_dmarc_detail = Column(Text)

    case = relationship("Case", back_populates="email")


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String, primary_key=True)
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"))
    type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    source = Column(String)
    risk = Column(String)
    status = Column(String)
    intelligence = Column(JSON)

    case = relationship("Case", back_populates="iocs")
