import csv
from time import time
import unicodedata
from groq import Groq
from groq import BadRequestError, RateLimitError
import base64
import os 
import sys
from dotenv import load_dotenv
from pathlib import Path
import json

sys.stdout.reconfigure(encoding='utf-8')
load_dotenv()

def normalize(s):
    if not s: return ""
    s = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in s if not unicodedata.combining(ch)).strip().lower()

def load_categories_from_local(path=Path("ai_runner/categories.csv").resolve()):
    codes_labels = []
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.reader(f, delimiter=';')
        for row in reader:
            if not row: continue
            code = row[0].strip()
            label = row[1].strip() if len(row)>1 else code
            codes_labels.append((code, label))
    return codes_labels

def clean_json_list(string_data):
    json_data = json.loads(string_data)
    """
    Usuwa obiekty z listy JSON, jeśli name, category lub category_code są None lub pustymi stringami.
    """
    return json.dumps([
        item for item in json_data
        if item.get("name") and item.get("category") and item.get("category_code")
    ], indent=2, ensure_ascii=False)

    

categories = load_categories_from_local()
normalized_map = {normalize(label): label for code,label in categories}
additional_info = sys.argv[2] if len(sys.argv) > 2 else None
prompt = f"""
    {additional_info or ""}
    Wyciągnij z tego fragmentu gazetki promocyjnej wszystkie okazje i daj mi tablicę jsonów o następujacej strukturze:
    {{
        "name": "string",
        "category_code": "string",
        "price_raw": "string|null",
        "price_value": "number|null",
        "price_alt": "string|null",
        "unit": "string|null",
        "discount_percent": "number|null",
        "promo_notes": "string|null",
    }}

    Lista dostępnych kategorii produktów to:
    {chr(10).join('- ' + label for _, label in categories)}
    Lista dostępnych kodów kategorii produktów to:
    {chr(10).join('- ' + code for code, _ in categories)}

    Zwróć tylko JSON array, ŻADNYCH komentarzy, wyjaśnień, ani znaczników markdown.
    Zwróć WYŁĄCZNIE poprawny JSON — zawsze tablicę (np. [] gdy brak okazji). Nie zwracaj pustego stringa ani żadnego innego tekstu.
    Jeśli cena nie jest podana to wypełnij pole price_alt informacją typu "1+1 gratis" lub "Drugi produkt -50%", ale nie pusty slogan typu "Super cena".
    Obraz, który dostaniesz może zawierać tekst typu "dowolna odzież, obuwie itd. 50% taniej", ale nie ma on być traktowany jako okazja promocyjna - również pomiń go w odpowiedzi, bierz pod uwagę tylko konkretne produkty jak np. "łaciate masło ekstra" czy "rzeźnik schab wieprzowy bez kości".
    Pamiętaj, żeby użyć podwójnych cudzysłowów " do oznaczenia stringów w JSON.
    Jeśli za pomocą OCR odczytasz jakiś tekst i będzie ewidentna literówka, np. "załać" zamiast "zapłać", to popraw to w odpowiedzi.
    """

text = ""
client = Groq(api_key=os.getenv("GROK_API_KEY"))
for attempt in range(5):
        try:
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
            temperature=0,
            top_p=1,
            stream=False,
            stop=None,
            )
            text = completion.choices[0].message.content
        except RateLimitError:
            time.sleep(2 ** attempt)
        except BadRequestError as e:
            print("CLI ARGS:", sys.argv, file=sys.stderr)
            err = e.args[0]  # lub e.response zależnie od klienta
            print("FAILED_GENERATION:", err)

text = text.strip()

if text.startswith("{") and not text.startswith("["):
    text = f"[{text}]"

import re
m = re.search(r'(\[.*\])', text, flags=re.S)
if m:
    json_text = m.group(1)
else:
    json_text = text

final_json = clean_json_list(json_text)

print(final_json)