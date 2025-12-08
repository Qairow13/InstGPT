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

# --------- ЗАГРУЗКА .env (для локальной разработки) ---------
load_dotenv()

# --------- НАСТРОЙКА ЛОГИРОВАНИЯ ---------
logging.basicConfig(
    level=logging.INFO,
    format="INFO:ig-webhook:%(message)s"
)

app = FastAPI()

# --------- ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ ---------
# Ровно такие имена, как у тебя в Render:
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "VERIFY_TOKEN")
APP_SECRET = os.getenv("APP_SECRET", "APP_SECRET")
PAGE_TOKEN = os.getenv("PAGE_TOKEN", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
SYSTEM_PROMPT = os.getenv("SYSTEM_PROMPT", "")
IG_USER_ID = os.getenv("IG_USER_ID", "")  # пока не используем, но пусть будет

client = OpenAI(api_key=OPENAI_API_KEY)


# --------- ВЕРИФИКАЦИЯ WEBHOOK (GET) ---------
@app.get("/webhook")
async def verify(request: Request):
    """
    Meta дергает этот эндпоинт, когда ты настраиваешь Webhook URL.
    Она шлёт hub.mode, hub.verify_token, hub.challenge.
    Мы должны вернуть challenge, если VERIFY_TOKEN совпадает.
    """
    params = request.query_params

    if params.get("hub.mode") == "subscribe" and params.get("hub.verify_token") == VERIFY_TOKEN:
        challenge = params.get("hub.challenge")
        logging.info("✅ Webhook verified")
        return PlainTextResponse(challenge)

    logging.info("❌ Webhook verification failed")
    return PlainTextResponse("Verification failed", status_code=403)


# --------- ПРИЁМ СОБЫТИЙ ОТ META (POST) ---------
@app.post("/webhook")
async def webhook(request: Request):
    """
    Сюда приходят все сообщения от Instagram/Facebook.
    """
    raw_body = await request.body()

    # --- Проверка подписи (без этого Meta может не доверять запросу) ---
    signature = request.headers.get("x-hub-signature-256", "")
    expected_signature = "sha256=" + hmac.new(APP_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        logging.info("❌ Bad signature")
        return {"status": "bad signature"}

    data = json.loads(raw_body.decode("utf-8"))
    logging.info(f"📩 incoming: {json.dumps(data, ensure_ascii=False)}")

    try:
        entry = data["entry"][0]
        messaging = entry.get("messaging", [])

        for msg in messaging:
            # Обычное сообщение
            if "message" in msg:
                sender = msg["sender"]["id"]
                text = msg["message"].get("text", "")

                logging.info(f"💬 Message from {sender}: {text}")

                # Генерируем ответ через GPT
                reply_text = generate_ai_reply(text)

                # Отправляем ответ пользователю
                send_message(sender, reply_text)

            # Отредактированное сообщение (просто залогируем)
            if "message_edit" in msg:
                logging.info(f"✏ Edited message: {msg['message_edit']}")

    except Exception as e:
        logging.info(f"⚠ error: {e}")

    return {"status": "ok"}


# --------- GPT: ГЕНЕРАЦИЯ ПРОДАЮЩЕГО ОТВЕТА ---------
def generate_ai_reply(user_text: str) -> str:
    """
    Здесь логика ИИ-продавца.
    SYSTEM_PROMPT берём из переменной окружения, если не задан — используем дефолт.
    """

    base_system_prompt = """
Вы — профессиональный ИИ-продавец Instagram-бизнеса.
Отвечайте кратко (1–3 предложения), вежливо, на «вы».
Всегда уточняйте потребности клиента и ведите к следующему шагу: выбор услуги/товара, оформление заказа или связь с менеджером.
Не используйте длинных простыней текста. Не упоминайте, что вы ИИ или бот.
Если клиент явно готов купить (пишет «хочу заказать», «как оплатить», «готов», «беру» и т.п.),
обязательно добавьте фразу: «Я передам ваш запрос менеджеру, он скоро свяжется с вами.»
"""

    system_prompt = SYSTEM_PROMPT or base_system_prompt

    if not OPENAI_API_KEY:
        logging.info("❗ OPENAI_API_KEY is not set")
        return "Извините, сейчас сервер не настроен. Попробуйте позже."

    try:
        completion = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_text},
            ],
        )

        reply = completion.choices[0].message.content.strip()
        if not reply:
            return "Извините, сейчас не могу ответить. Напишите, пожалуйста, чуть позже."

        return reply

    except Exception as e:
        logging.info(f"OpenAI error: {e}")
        return "Извините, сейчас есть небольшие технические неполадки. Менеджер ответит вам позже."


# --------- ОТПРАВКА СООБЩЕНИЯ В DIRECT ---------
def send_message(recipient_id: str, text: str):
    """
    Отправляем текстовое сообщение пользователю через Graph API.
    """
    url = f"https://graph.facebook.com/v21.0/me/messages?access_token={PAGE_TOKEN}"

    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": text}
    }

    r = requests.post(url, json=payload)
    logging.info(f"📤 outgoing: {r.text}")

    return r.text


# --------- ЛОКАЛЬНЫЙ ЗАПУСК ---------
if __name__ == "__main__":
    # Локально можно запустить так: python main.py
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
