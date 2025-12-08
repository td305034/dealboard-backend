import csv
import unicodedata
from groq import Groq
import base64
import os 
import sys
from dotenv import load_dotenv

load_dotenv()

def normalize(s):
    if not s: return ""
    s = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in s if not unicodedata.combining(ch)).strip().lower()

def load_categories_from_local(path="categories.csv"):
    codes_labels = []
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.reader(f, delimiter=';')
        for row in reader:
            if not row: continue
            code = row[0].strip()
            label = row[1].strip() if len(row)>1 else code
            codes_labels.append((code, label))
    return codes_labels

categories = load_categories_from_local()
normalized_map = {normalize(label): label for code,label in categories}
additional_info = sys.argv[2] if len(sys.argv) > 2 else None
prompt = f"""
    {additional_info or ""}
    Wyciągnij z tego fragmentu gazetki promocyjnej wszystkie okazje i daj mi jsona o następujacej strukturze:
     {{
        "name": "string",
        "category": "string",
        "category_code": "string",
        "price_raw": "string|null",
        "price_value": "number|null",
        "price_alt": "string|null",
        "unit": "string|null",
        "discount_percent": "number|null",
        "promo_notes": "string|null",
        "page": "integer" 
     }}
    
    Lista dostępnych kategorii produktów to:
    {chr(10).join('- ' + label for _, label in categories)}
    Lista dostępnych kodów kategorii produktów to:
    {chr(10).join('- ' + code for code, _ in categories)}

    Zwróć tylko JSON, bez żadnego dodatkowego tekstu. 
    Nie każda strona musi zawierać okazje, w takim wypadku zwróć pusty string.
    Jeśli cena nie jest podana to wypełnij pole price_alt informacją typu "1+1 gratis" lub "Drugi produkt -50%".
    Obraz, który dostaniesz może zawierać tekst typu "dowolna odzież, obuwie itd. 50% taniej", ale nie ma on być traktowany jako okazja promocyjna - również pomiń go w odpowiedzi, bierz pod uwagę tylko konkretne produkty jak np. "łaciate masło ekstra" czy "rzeźnik schab wieprzowy bez kości".
    """ 

client = Groq(api_key=os.getenv("GROK_API_KEY"))
completion = client.chat.completions.create(
    model="meta-llama/llama-4-scout-17b-16e-instruct",
    messages=[
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": prompt
                },
                {
                    "type": "image_url",
                    "image_url": {
                        "url": sys.argv[1]
                    }
                }
            ]
        }
    ],
    stream=False,
    response_format={"type": "json_object"},
    stop=None,
)
print(completion.choices[0].message.content)