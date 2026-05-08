import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def get_ssl_info(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path  # Витягуємо домен
    
    context = ssl.create_default_context()
    
    try:
        # Встановлюємо з'єднання на порт 443 (HTTPS) з таймаутом 3 сек
        with socket.create_connection((hostname, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Парсимо дату закінчення
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.now()).days
                
                # Отримуємо видавця (Issuer)
                issuer_info = dict(x[0] for x in cert['issuer'])
                issuer_name = issuer_info.get('organizationName', 'Unknown')

                return {
                    "valid": True,
                    "issuer": issuer_name,
                    "expires_date": not_after.strftime("%Y-%m-%d"),
                    "days_left": days_left,
                    "is_suspicious": days_left < 30 or "Let's Encrypt" in issuer_name 
                    # Let's Encrypt часто використовують для фішингових сайтів
                }

    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
            "is_suspicious": True # Якщо SSL немає або він битий - підозріло
        }
