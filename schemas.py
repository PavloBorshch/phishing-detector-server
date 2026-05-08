from pydantic import BaseModel
from typing import Optional, List

# Що приходить від клієнта
class URLCheckRequest(BaseModel):
    url: str
    dom_content: Optional[str] = None
    logo_url: Optional[str] = None

# Частина відповіді про SSL
class SSLInfo(BaseModel):
    valid: bool
    issuer: Optional[str] = None
    expires_date: Optional[str] = None
    is_suspicious: bool = False

# Повна відповідь сервера
class AnalysisResult(BaseModel):
    url: str
    status: str          # "safe", "suspicious", "danger"
    risk_score: int      # 0 - 100
    details: List[str]   # Список причин
    ssl_info: Optional[SSLInfo] = None
    