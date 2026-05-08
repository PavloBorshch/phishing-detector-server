import os
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select

from schemas import URLCheckRequest, AnalysisResult, SSLInfo
from models import TrustedResource
from services.ssl_checker import get_ssl_info
from services.url_analyzer import analyze_url_risk
from services.image_analyzer import compute_phash_from_url
from services.phash_analyzer import analyze_logo_phash
from services.dom_analyzer import analyze_dom_content

# Отримуємо рядок підключення
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://user:pass@localhost/dbname")

# Виправляємо префікс незалежно від того, postgres це чи postgresql
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# Створення асинхронного двигуна
engine = create_async_engine(DATABASE_URL, echo=True)

# Фабрика сесій
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@app.post("/check-url", response_model=AnalysisResult)
async def check_url_endpoint(request: URLCheckRequest, db: AsyncSession = Depends(get_db)):
    url = request.url
    if not url.startswith("http"):
        url = "https://" + url
    
    # Тимчасовий лог для перевірки передачі DOM
    if request.dom_content:
        print(f"[{url}] Отримано DOM розміром {len(request.dom_content)} символів")
    else:
        print(f"[{url}] DOM не передано")
    
    # Обробка Логотипу та pHash
    phash_analysis = None
    if request.logo_url:
        print(f"[{url}] Знайдено логотип: {request.logo_url}")
        phash_value = await compute_phash_from_url(request.logo_url)
        if phash_value:
            print(f"[{url}] Обчислено pHash: {phash_value}")
            # Викликаємо функцію аналізу pHash
            phash_analysis = await analyze_logo_phash(url, phash_value, db)
    else:
        print(f"[{url}] Логотип не знайдено на сторінці")
    
    # Передаємо db у функцію аналізу
    url_analysis = await analyze_url_risk(url, db)
    
    final_score = url_analysis["score"]
    # Робимо копію списку деталей, щоб безпечно додавати туди нові рядки
    details = list(url_analysis["details"])
    current_status = url_analysis["status"]

    # Додаємо результати pHash аналізу до загальної оцінки
    if phash_analysis:
        if phash_analysis["status"] == "danger":
            current_status = "danger"
            final_score = max(final_score, phash_analysis["score"])
            details.append(phash_analysis["details"])
        elif phash_analysis["status"] == "safe":
            details.append(phash_analysis["details"])

    # Аналіз DOM-структури
    if request.dom_content:
        # Витягуємо еталонні сайти з бази для перевірки крадіжки брендів
        result = await db.execute(select(TrustedResource))
        trusted_sites = result.scalars().all()
        
        dom_analysis = analyze_dom_content(url, request.dom_content, trusted_sites)
        final_score += dom_analysis["score"]
        details.extend(dom_analysis["details"])

        # Якщо DOM аналізатор знайшов багато загроз, оновлюємо статус
        if final_score > 70:
            current_status = "danger"

    # Робимо масив "плоским"
    flat_details = []
    for item in details:
        if isinstance(item, list):
            flat_details.extend(item)
        else:
            flat_details.append(item)

    # Видаляємо дублікати
    details = list(dict.fromkeys(flat_details))

    # Якщо виявлено небезпеку - виходимо одразу
    if current_status == "danger":
         return AnalysisResult(
            url=url,
            status="danger",
            risk_score=min(final_score, 100),  # Обмежуємо бал до 100
            details=details,
            ssl_info=None
        )

    # SSL перевірка
    ssl_data = get_ssl_info(url)
    
    ssl_model = SSLInfo(
        valid=ssl_data["valid"],
        issuer=ssl_data.get("issuer"),
        expires_date=ssl_data.get("expires_date"),
        is_suspicious=ssl_data.get("is_suspicious")
    )

    if not ssl_data["valid"]:
        final_score += 50
        details.append("DETAIL_SSL_INVALID")
    elif ssl_data["is_suspicious"]:
        final_score += 20
        details.append("DETAIL_SSL_SUSPICIOUS")

    status = "safe"
    if final_score > 70: status = "danger"
    elif final_score > 30: status = "suspicious"
    
    # Якщо сайт в білому списку, статус завжди safe, навіть якщо SSL підозрілий
    if url_analysis["status"] == "safe" and current_status != "danger":
        status = "safe"
        final_score = 0

    # Очищуємо дублікати ще раз на випадок збігів з SSL повідомленнями
    details = list(dict.fromkeys(details))

    return AnalysisResult(
        url=url,
        status=status,
        risk_score=min(final_score, 100),  # Обмежуємо бал до 100
        details=details,
        ssl_info=ssl_model
    )

# venv\Scripts\activate
# python -m uvicorn main:app --reload