import asyncio
from database import engine, Base, AsyncSessionLocal
from models import TrustedResource
from sqlalchemy import select

# Приклади новинних сайтів
NEWS_SITES = [
    {
        "domain": "pravda.com.ua", 
        "name": "Українська Правда", 
        "logo_phashes": ["93cc6c33c79c91c6"]
    },
    {
        "domain": "tsn.ua", 
        "name": "ТСН", 
        "logo_phashes": ["9a9a6565339ace64"]
    },
    {
        "domain": "unian.ua", 
        "name": "УНІАН", 
        "logo_phashes": ["efe2801e68c1a7b6"]
    },
    {
        "domain": "suspilne.media", 
        "name": "Суспільне Новини", 
        "logo_phashes": ["aa33558caa73758c"]
    },
    {
        "domain": "bbc.com", 
        "name": "BBC News", 
        "logo_phashes": ["aa0080002a008000"]
    },
    {
        "domain": "edition.cnn.com", 
        "name": "CNN", 
        "logo_phashes": ["9dcd7227999c2266"]
    },
    {
        "domain": "nytimes.com", 
        "name": "The New York Times", 
        "logo_phashes": ["c3c33c3cc3c33c3c"]
    },
]

async def init_models():
    async with engine.begin() as conn:
        # Видалення старих таблиць (dev)
        # await conn.run_sync(Base.metadata.drop_all)
        
        # Створюємо нові таблиці
        await conn.run_sync(Base.metadata.create_all)
    
    print("Old tables dropped. New tables created successfully.")

async def seed_data():
    async with AsyncSessionLocal() as session:
        print("Seeding database with news sites...")
        
        for site in NEWS_SITES:
            # Перевіряємо наявність домену
            result = await session.execute(select(TrustedResource).where(TrustedResource.domain == site["domain"]))
            exists = result.scalar_one_or_none()
            
            if not exists:
                new_site = TrustedResource(
                    domain=site["domain"],
                    organization_name=site["name"],
                    logo_phashes=site.get("logo_phashes")
                )
                session.add(new_site)
                print(f"Added: {site['name']} (pHash: {'Yes' if site.get('logo_phash') else 'No'})")
            else:
                # Якщо сайт вже є, але ми додали хеш у код, оновимо його в базі
                if site.get("logo_phash") and exists.logo_phash != site.get("logo_phash"):
                    exists.logo_phash = site.get("logo_phash")
                    print(f"Updated pHash for: {site['name']}")
                else:
                    print(f"Skipped (already exists): {site['name']}")
        
        await session.commit()
    print("Seeding complete.")

async def main():
    await init_models()
    await seed_data()

if __name__ == "__main__":
    asyncio.run(main())