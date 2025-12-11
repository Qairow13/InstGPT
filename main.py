import os
import hmac
import hashlib
import json
import logging

import requests
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
import uvicorn

from openai import OpenAI
from dotenv import load_dotenv

# --------- ЗАГРУЗКА .env ---------
load_dotenv()

# --------- ЛОГИ ---------
logging.basicConfig(
    level=logging.INFO,
    format="INFO:ig-webhook:%(message)s"
)

app = FastAPI()

# --------- ENV ---------
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "VERIFY_TOKEN")
APP_SECRET = os.getenv("APP_SECRET", "APP_SECRET")
PAGE_TOKEN = os.getenv("PAGE_TOKEN", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
SYSTEM_PROMPT = os.getenv("SYSTEM_PROMPT", "")

client = OpenAI(api_key=OPENAI_API_KEY)

# --------- ВЕРИФИКАЦИЯ WEBHOOK ---------
@app.get("/webhook")
async def verify(request: Request):
    params = request.query_params

    if params.get("hub.mode") == "subscribe" and params.get("hub.verify_token") == VERIFY_TOKEN:
        challenge = params.get("hub.challenge")
        logging.info("✅ Webhook verified successfully")
        return PlainTextResponse(challenge)

    logging.info("❌ Webhook verification failed")
    return PlainTextResponse("Verification failed", status_code=403)


# --------- ПРИЁМ И ОТВЕТ МЕССЕНДЖЕРА ---------
@app.post("/webhook")
async def webhook(request: Request):
    raw_body = await request.body()

    # проверка подписи
    signature = request.headers.get("x-hub-signature-256", "")
    expected_signature = "sha256=" + hmac.new(APP_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        logging.info("❌ Signature mismatch")
        return {"status": "bad signature"}

    data = json.loads(raw_body.decode("utf-8"))
    logging.info(f"📩 incoming event: {json.dumps(data, ensure_ascii=False)}")

    try:
        for entry in data.get("entry", []):
            for msg in entry.get("messaging", []):
                message = msg.get("message")

                # пропуск системных событий
                if not message:
                    continue

                # нельзя отвечать на свои же сообщения
                if message.get("is_echo"):
                    logging.info("↩ Skip echo")
                    continue

                sender_id = msg["sender"]["id"]
                text = message.get("text", "")

                logging.info(f"💬 Message from {sender_id}: {text}")

                # Генерация ответа GPT
                reply = generate_ai_reply(text)

                # Отправка ответа
                send_message(sender_id, reply)

                logging.info(f"✅ Reply sent to {sender_id}")

    except Exception as e:
        logging.info(f"⚠ ERROR: {e}")

    return {"status": "ok"}


# --------- GPT: ЛОГИКА ОТВЕТА ---------
def generate_ai_reply(user_text: str) -> str:

    base_prompt = """
Ты — виртуальный продавец магазина бытовой химии Instagram @optomtovary89.

Правила общения:
1. НЕ ПРИВЕТСТВУЙ, если клиент писал раньше — сразу переходи к ответу.
2. Отвечай коротко, по существу, как реальный продавец.
3. Помни ассортимент: бытовая химия, стирка, уборка, посуда, освежители, гели, порошки.
4. Если клиент спрашивает "что есть?" — выдавай список категорий и предложи уточнить бюджет.
5. Если вопрос не по теме — мягко возвращай к товарам.
6. Никогда не используй длинные официозные фразы. Отвечай как продавец с реального аккаунта.
"""

    system_prompt = SYSTEM_PROMPT or base_prompt

    if not OPENAI_API_KEY:
        return "Извините, сервис временно недоступен."

    try:
        completion = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_text},
            ],
        )

        reply = completion.choices[0].message.content.strip()
        return reply or "Напишите, что именно вас интересует."

    except Exception as e:
        logging.info(f"❌ OpenAI error: {e}")
        return "Пока не могу ответить — попробуйте чуть позже."


# --------- ОТПРАВКА СООБЩЕНИЯ В INSTAGRAM ---------
def send_message(recipient_id: str, text: str):
    url = f"https://graph.facebook.com/v24.0/me/messages?access_token={PAGE_TOKEN}"

    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": text}
    }

    r = requests.post(url, json=payload)
    logging.info(f"📤 outgoing: {r.text}")

    return r.text


# --------- ЛОКАЛЬНЫЙ ЗАПУСК ---------
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
