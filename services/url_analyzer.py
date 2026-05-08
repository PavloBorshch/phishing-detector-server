import textdistance
from urllib.parse import urlparse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone, timedelta
from models import TrustedResource, DomainAnalysisCache
from services.vt_client import get_vt_domain_info

async def analyze_url_risk(url: str, db: AsyncSession) -> dict:
    parsed = urlparse(url)
    domain = (parsed.netloc or parsed.path).replace("www.", "")
    
    # Перевірка білого списку
    result = await db.execute(select(TrustedResource).where(TrustedResource.domain == domain))
    trusted_site = result.scalar_one_or_none()
    
    if trusted_site:
        return {
            "status": "safe",
            "score": 0,
            "details": [f"Офіційний ресурс: {trusted_site.organization_name}"]
        }
    
    # Кешування результатів з VT 
    cache_result = await db.execute(select(DomainAnalysisCache).where(DomainAnalysisCache.domain == domain))
    cached_data = cache_result.scalar_one_or_none()
    
    vt_data = None
    now = datetime.now(timezone.utc)
    
    # Чи потрібен запит до API
    needs_api_call = True
    if cached_data:
        last_checked = cached_data.last_checked
        if last_checked.tzinfo is None:
            last_checked = last_checked.replace(tzinfo=timezone.utc)
        if (now - last_checked) < timedelta(hours=24):
            needs_api_call = False

    if needs_api_call:
        print(f"Робимо запит до VirusTotal для {domain}...")
        vt_info = await get_vt_domain_info(domain)
        
        if vt_info:
            if not cached_data:
                cached_data = DomainAnalysisCache(domain=domain)
                db.add(cached_data)
            
            cached_data.creation_date = vt_info["creation_date"]
            cached_data.malicious_votes = vt_info["malicious_votes"]
            cached_data.suspicious_votes = vt_info["suspicious_votes"]
            cached_data.last_checked = now
            
            await db.commit()
            vt_data = vt_info
    else:
        print(f"Беремо дані з кешу бази даних для {domain}...")
        vt_data = {
            "creation_date": cached_data.creation_date,
            "malicious_votes": cached_data.malicious_votes,
            "suspicious_votes": cached_data.suspicious_votes
        }

    # Розрахунок ризику
    risk_score = 35
    details = ["DETAIL_NOT_IN_TRUSTED_LIST"]
    status = "suspicious"

    # Тайпосквотинг
    all_trusted = await db.execute(select(TrustedResource))
    trusted_list = all_trusted.scalars().all()
    for site in trusted_list:
        similarity = textdistance.levenshtein.normalized_similarity(domain, site.domain)
        if 0.75 < similarity < 1.0:
            return {
                "status": "danger",
                "score": 95,
                # Передаємо код і одразу два дані як один параметр для {brand}
                "details": [f"DETAIL_TYPOSQUATTING:{site.organization_name} ({site.domain})"]
            }

    print(f"DEBUG: vt_data for {url}: {vt_data}")
    # Обрахунок даних з VirusTotal 
    if vt_data:
        total_bad_votes = vt_data["malicious_votes"] + vt_data["suspicious_votes"]
        if total_bad_votes > 0:
            risk_score += total_bad_votes * 10
            # Передаємо код та кількість голосів
            details.append(f"DETAIL_VT_VOTES:{total_bad_votes}")
        else:
            # Додаємо повідомлення про відсутність скарг
            details.append("DETAIL_VT_CLEAN")
        
        
        if vt_data["creation_date"]:
            # Конвертація Unix Timestamp у звичайну дату
            creation_dt = datetime.fromtimestamp(vt_data["creation_date"], tz=timezone.utc)
            age_days = (now - creation_dt).days
            
            if age_days < 30:
                risk_score += 50
                # Передаємо код та кількість днів
                details.append(f"DETAIL_AGE_CRITICAL:{age_days}")
            elif age_days < 180:
                risk_score += 20
                details.append(f"DETAIL_AGE_SUSPICIOUS:{age_days}")
            else:
                details.append(f"DETAIL_AGE_SAFE:{age_days}")
        else:
             details.append("DETAIL_AGE_UNKNOWN")
    # Фінальний вердикт
    if risk_score > 70: status = "danger"
    elif risk_score > 30: status = "suspicious"

    return {
        "status": status,
        "score": min(risk_score, 100), # Максимум 100 балів
        "details": details
    }