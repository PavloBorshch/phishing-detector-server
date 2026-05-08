from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.sql import func
from database import Base

class TrustedResource(Base):
    __tablename__ = "trusted_resources"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True)
    organization_name = Column(String)

    logo_phashes = Column(JSON, nullable=True) 
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class DomainAnalysisCache(Base):
    __tablename__ = "domain_analysis_cache"

    domain = Column(String, primary_key=True, index=True)
    ssl_data = Column(JSON, nullable=True)            # Зберігаємо інформацію про сертифікат
    risk_score = Column(Integer, default=0)
    verdict = Column(String)                          # "safe", "danger"

    creation_date = Column(Integer, nullable=True)     
    malicious_votes = Column(Integer, default=0)       
    suspicious_votes = Column(Integer, default=0)

    last_checked = Column(DateTime(timezone=True), server_default=func.now())

class AnalysisLog(Base):
    __tablename__ = "analysis_logs"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String)
    verdict = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
