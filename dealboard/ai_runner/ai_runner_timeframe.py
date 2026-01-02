import csv
import time
import unicodedata
from groq import Groq
from groq import BadRequestError, RateLimitError
import base64
import os
import sys
from dotenv import load_dotenv
from pathlib import Path
import json
from datetime import date

sys.stdout.reconfigure(encoding='utf-8')
load_dotenv()

def normalize_dates(dates):
    today = date.today()
    current_year = today.year

    for d in dates:
        if d.get("day") is None or d.get("month") is None:
            d["day"] = today.day
            d["month"] = today.month
            d["year"] = current_year
        elif d["year"] is None:
            d["year"] = current_year

    d1 = date(dates[0]["year"], dates[0]["month"], dates[0]["day"])
    d2 = date(dates[1]["year"], dates[1]["month"], dates[1]["day"])

    if d1 > d2:
        dates[0]["year"] -= 1

    return dates

PROMPT_HAS_DATE = f"""
Czy na tym obrazie znajduje się JEDNOZNACZNIE WIDOCZNA i CZYTELNA
data ważności gazetki w formacie OD–DO (dwie konkretne daty)?

Odpowiedz WYŁĄCZNIE jednym słowem:
YES
albo
NO

Nie dodawaj żadnych innych znaków ani komentarzy.
"""

client = Groq(api_key=os.getenv("GROK_API_KEY"))

resp = client.chat.completions.create(
    model="meta-llama/llama-4-scout-17b-16e-instruct",
    messages=[{
        "role": "user",
        "content": [
            {"type": "text", "text": PROMPT_HAS_DATE},
            {"type": "image_url", "image_url": {"url": sys.argv[1]}}
        ]
    }],
    temperature=0,
)

answer = resp.choices[0].message.content.strip()

if answer != "YES":
    response = normalize_dates([
        {"day": None, "month": None, "year": None},
        {"day": None, "month": None, "year": None}
    ])
    print(json.dumps(response))
    sys.exit(0)

PROMPT_EXTRACT_DATES = f"""
    Wyciągnij z obrazu datę OD kiedy i datę DO kiedy obowiązuje oferta.

    Zwróć WYŁĄCZNIE poprawny JSON array z DWOMA obiektami:
    [
      {{ "day": number|null, "month": number|null, "year": number|null }},
      {{ "day": number|null, "month": number|null, "year": number|null }}
    ]

    Zasady:
    - Nie zgaduj.
    - Nie rekonstruuj.
    - Jeśli rok nie jest widoczny, zwróć null jako year.
    - Jeśli którakolwiek z dat nie jest w 100% czytelna, zwróć null dla jej pól.
    - ŻADNEGO innego tekstu poza JSON.
    """

text = ""
completion = client.chat.completions.create(
model="meta-llama/llama-4-scout-17b-16e-instruct",
messages=[
{
    "role": "user",
    "content": [
        {
            "type": "text",
            "text": PROMPT_EXTRACT_DATES
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

data = json.loads(json_text)
if not isinstance(data, list) or len(data) != 2:
    raise ValueError("Model must return JSON array with exactly 2 elements")

normalized = normalize_dates(data)

print(json.dumps(normalized, ensure_ascii=False))
