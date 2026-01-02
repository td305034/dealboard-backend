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
    """
    Przyjmuje string zawierający JSON array lub pojedyncze obiekty.
    Zwraca poprawną tablicę JSON tylko z pełnymi obiektami.
    """
    string_data = string_data.strip()
    items = []

    # jeśli mamy poprawną tablicę JSON, po prostu parsujemy
    if string_data.startswith("[") and string_data.endswith("]"):
        try:
            items = json.loads(string_data)
        except json.JSONDecodeError:
            # wpadliśmy w sytuację „luźnych obiektów JSON”
            import re
            pattern = re.compile(r'\{.*?\}', re.S)
            for match in pattern.finditer(string_data):
                try:
                    obj = json.loads(match.group())
                    items.append(obj)
                except json.JSONDecodeError:
                    continue
    else:
        # same obiekty JSON jeden po drugim
        import re
        pattern = re.compile(r'\{.*?\}', re.S)
        for match in pattern.finditer(string_data):
            try:
                obj = json.loads(match.group())
                items.append(obj)
            except json.JSONDecodeError:
                continue

    # filtrujemy tylko pełne obiekty
    cleaned = [
        item for item in items
        if item.get("name") and item.get("category_code") and item.get("category_code") != ""
    ]

    return json.dumps(cleaned, indent=2, ensure_ascii=False)



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

    Lista dostępnych kodów kategorii produktów to:
    {chr(10).join('- ' + code for code, _ in categories)}

    Zwróć tylko JSON array, ŻADNYCH komentarzy, wyjaśnień, ani znaczników markdown.
    Zwróć WYŁĄCZNIE poprawny JSON — zawsze tablicę (np. [] gdy brak okazji). Nie zwracaj pustego stringa ani żadnego innego tekstu.
    Jeśli cena nie jest podana to wypełnij pole price_alt jakąkolwiek informacją o cenie, np. "1+1 gratis" lub "Drugi produkt -50%" czy chociażby "20zł taniej",
    ale nie pustym sloganem typu "Supercena". Nie wpisuj nigdzie "supercena", użytkownika to nie interesuje.
    Pamiętaj, żeby użyć podwójnych cudzysłowów " do oznaczenia stringów w JSON.
    Jeśli za pomocą OCR odczytasz jakiś tekst i będzie ewidentna literówka, np. "załać" zamiast "zapłać", to popraw to w odpowiedzi.
    """

text = ""
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
temperature=0,
top_p=1,
stream=False,
stop=None,
)
text = completion.choices[0].message.content

text = text.strip()

if text.startswith("{") and not text.startswith("["):
    text = f"[{text}]"

import re
start = text.find('[')
end = text.rfind(']')
json_text = text[start:end+1] if start != -1 and end != -1 else text

final_json = clean_json_list(json_text)

print(final_json)