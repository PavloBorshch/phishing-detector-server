import imagehash
from urllib.parse import urlparse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import TrustedResource

# Порівнює pHash логотипу сайту з еталонними хешами з бази даних.
async def analyze_logo_phash(url: str, target_phash_str: str, db: AsyncSession) -> dict | None:
    if not target_phash_str:
        return None

    # Ініціалізуємо змінні перед початком перевірок
    score = 0
    details = []
    status = "neutral"

    # Витягуємо чистий домен з URL
    parsed = urlparse(url)
    current_domain = (parsed.netloc or parsed.path).replace("www.", "")

    # Перетворюємо рядок у спеціальний об'єкт хешу
    try:
        target_hash = imagehash.hex_to_hash(target_phash_str)
    except ValueError:
        return None

    # Завантажуємо всі сайти, де є хоча б один хеш
    result = await db.execute(select(TrustedResource).where(TrustedResource.logo_phashes.isnot(None)))
    trusted_sites = result.scalars().all()

    # СТВОРЮЄМО ЗМІННУ ДО ПОЧАТКУ ЦИКЛІВ
    match_found = False

    for site in trusted_sites:
        # Перевіряємо, чи є список хешів і чи він не порожній
        if not isinstance(site.logo_phashes, list):
            continue

        # Проходимося по кожному еталонному варіанту логотипа цього сайту
        for ref_hash_str in site.logo_phashes:
            try:
                trusted_hash = imagehash.hex_to_hash(ref_hash_str)
                distance = target_hash - trusted_hash

                # Якщо ціль збіглася ХОЧА Б З ОДНИМ варіантом
                if distance <= 8:
                    if current_domain != site.domain:
                        score += 100
                        details.append(f"DETAIL_PHASH_MATCH:{site.organization_name}")
                        status = "danger"
                    
                    # Збіг знайдено (неважливо, на чужому чи своєму домені)
                    match_found = True
                    break  # Перериваємо внутрішній цикл (цикл по logo_phashes)
                    
            except ValueError:
                continue
        
        # ПЕРЕВІРЯЄМО ПРАПОРЕЦЬ ТУТ, ЩОБ ПЕРЕРВАТИ ЗОВНІШНІЙ ЦИКЛ
        if match_found:
            break  # Перериваємо зовнішній цикл (цикл по trusted_sites)

    if score > 0:
        return {
            "status": status,
            "score": score,
            "details": details
        }
    else:
        return None