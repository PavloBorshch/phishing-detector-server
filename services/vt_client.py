import os
import httpx
from dotenv import load_dotenv

# Завантажуємо api з .env файлу
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

async def get_vt_domain_info(domain: str) -> dict:
    if not VT_API_KEY:
        print("Помилка: VT_API_KEY не знайдено")
        return None

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    async with httpx.AsyncClient() as client:
        try:
            # timeout=5.0 в разі довгої відповіді від VT
            response = await client.get(url, headers=headers, timeout=5.0)
            
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                
                return {
                    "creation_date": data.get("creation_date"),
                    "malicious_votes": stats.get("malicious", 0),
                    "suspicious_votes": stats.get("suspicious", 0)
                }
            else:
                print(f"VT API Error: {response.status_code}")
                return None
        except Exception as e:
            print(f"Помилка з'єднання з VT: {e}")
            return None
