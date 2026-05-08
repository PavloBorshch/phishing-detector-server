import httpx
from PIL import Image, ImageOps
import imagehash
from io import BytesIO

# Завантажує зображення за URL та обчислює його перцептивний хеш (pHash)
async def compute_phash_from_url(img_url: str) -> str | None:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(img_url, timeout=5.0)
            
            if response.status_code == 200:
                img = Image.open(BytesIO(response.content))
                
                # Конвертуємо в RGBA
                img = img.convert("RGBA")
                
                # Обрізаємо прозорі краї
                bbox = img.getbbox()
                if bbox:
                    img = img.crop(bbox)
                
                # Накладаємо на білий фон
                background = Image.new("RGB", img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[3]) 
                
                # Тепер рахуємо хеш від стандартизованого зображення
                return str(imagehash.phash(background))
                
            else:
                print(f"Не вдалося завантажити логотип. Статус: {response.status_code}")
                
    except Exception as e:
        print(f"Помилка обробки логотипу: {e}")
        
    return None