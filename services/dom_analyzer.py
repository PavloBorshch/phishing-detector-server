from bs4 import BeautifulSoup
from urllib.parse import urlparse

def analyze_dom_content(url: str, dom_content: str, trusted_sites: list) -> dict:
    if not dom_content:
        return {"score": 0, "details": []}

    # Використовуємо вбудований парсер
    soup = BeautifulSoup(dom_content, 'html.parser') 
    parsed_url = urlparse(url)
    current_domain = (parsed_url.netloc or parsed_url.path).replace("www.", "")

    score = 0
    details = []

    # Аналіз форм та фішингу
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '').lower()
        
        # Перевірка незахищеного протоколу
        if action.startswith('http://'):
            score += 50
            details.append("DETAIL_INSECURE_FORM")
        
        # Перевірка відправки даних на чужий домен
        if action.startswith('http') and current_domain not in action:
            score += 40
            details.append("DETAIL_EXFILTRATION")
        
        # Пошук прихованих або явних полів для паролів
        pass_inputs = form.find_all('input', type='password')
        if pass_inputs:
            score += 20
            details.append("DETAIL_PASSWORD_INPUT")

    # Виявлення клонів
    title_tag = soup.title
    title_text = title_tag.string.lower() if title_tag and title_tag.string else ""
    
    og_site_name = soup.find('meta', property='og:site_name')
    site_name_text = og_site_name.get('content', '').lower() if og_site_name else ""

    # Рахуємо всі посилання на сторінці
    links = soup.find_all('a', href=True)
    total_links = len(links)
    trusted_external_links_count = 0

    for site in trusted_sites:
        org_name = site.organization_name.lower()
        trusted_domain = site.domain.lower()
        
        # Перевірка крадіжки бренду в Title
        if (org_name in title_text or trusted_domain in title_text):
            if current_domain != trusted_domain:
                score += 60  
                details.append(f"DETAIL_DOM_TITLE:{site.organization_name}")

        # Перевірка крадіжки бренду в Meta-тегах (наприклад, og:site_name)
        if (org_name in site_name_text):
            if current_domain != trusted_domain:
                score += 60 
                details.append(f"DETAIL_DOM_META:{site.organization_name}")
        
        # Аналіз "мертвих" посилань (Link Hijacking)
        if total_links > 15:
            # Шукаємо, скільки посилань ведуть на оригінальний сайт
            link_matches = sum(1 for link in links if trusted_domain in link['href'].lower() and current_domain not in link['href'].lower())
            trusted_external_links_count += link_matches

    # Якщо більше 25% всіх посилань ведуть на один із відомих ЗМІ, а ми не на ньому
    if total_links > 15 and (trusted_external_links_count / total_links) > 0.25:
        score += 60
        details.append("DETAIL_LINK_HIJACKING")

    return {
        "score": score,
        # Видаляємо можливі дублікати попереджень, зберігаючи порядок
        "details": list(dict.fromkeys(details)) 
    }