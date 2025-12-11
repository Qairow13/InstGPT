import os
import hmac
import hashlib
import json
import logging
from collections import defaultdict, deque

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
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "VERIFY_TOKEN")
APP_SECRET = os.getenv("APP_SECRET", "APP_SECRET")
PAGE_TOKEN = os.getenv("PAGE_TOKEN", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
SYSTEM_PROMPT = os.getenv("SYSTEM_PROMPT", "")
IG_USER_ID = os.getenv("IG_USER_ID", "")

client = OpenAI(api_key=OPENAI_API_KEY)

# --------- ПАМЯТЬ ДЛЯ ДИАЛОГОВ ---------
# Для каждого пользователя храним до 10 последних сообщений
MAX_CONTEXT_MESSAGES = 10
conversations = defaultdict(lambda: deque(maxlen=MAX_CONTEXT_MESSAGES))


def add_to_history(user_id: str, role: str, content: str):
    """Сохранить сообщение в истории диалога с пользователем."""
    conversations[user_id].append({"role": role, "content": content})


def get_history(user_id: str):
    """Вернуть историю для пользователя в виде списка messages."""
    return list(conversations[user_id])


# --------- ВЕРИФИКАЦИЯ WEBHOOK (GET) ---------
@app.get("/webhook")
async def verify(request: Request):
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
        entry = data["entry"][0]
        messaging = entry.get("messaging", [])

        for msg in messaging:
            message = msg.get("message")

            # если нет блока message — например, это событие message_edit и т.п.
            if not message:
                continue

            # игнорируем эхо (сообщения, отправленные самим бизнес-аккаунтом)
            if message.get("is_echo"):
                logging.info("↩ Skip echo")
                continue

            sender_id = msg["sender"]["id"]
            text = message.get("text", "")

            logging.info(f"💬 Message from {sender_id}: {text}")

            # Добавляем запрос в историю диалога
            add_to_history(sender_id, "user", text)

            # Генерируем ответ с учётом истории
            reply_text = generate_ai_reply(sender_id)

            # Добавляем ответ в историю
            add_to_history(sender_id, "assistant", reply_text)

            # Отправляем ответ
            send_message(sender_id, reply_text)
            logging.info(f"✅ Reply sent to {sender_id}")

    except Exception as e:
        logging.info(f"⚠ error: {e}")

    return {"status": "ok"}


# --------- GPT: ГЕНЕРАЦИЯ ПРОДАЮЩЕГО ОТВЕТА ---------
def generate_ai_reply(user_id: str) -> str:
    """
    Логика ИИ-продавца с короткой памятью по диалогу.
    """

    base_system_prompt = """
Ты — виртуальный продавец магазина бытовой химии в Instagram-аккаунте @optomtovary89.

Главные правила общения:
1. Приветствуй клиента ТОЛЬКО в самом начале диалога. Если в истории есть предыдущие сообщения, сразу отвечай по делу без повторных приветствий и представлений.
2. Отвечай коротко и по существу, без лишних общих фраз.
3. Всегда помни, что ты консультант по бытовой химии и товарам из этого Instagram.
4. Если спрашивают не по теме магазина — мягко возвращай разговор к товарам и вопросам по покупкам.
5. Если информации не хватает, честно скажи, чего именно не хватает, и попроси уточнить: объём, фото, пример и т.д.

Когда продолжаешь диалог, ориентируйся на предыдущие сообщения в истории и не начинай с нуля.
"""

    system_prompt = SYSTEM_PROMPT or base_system_prompt

    if not OPENAI_API_KEY:
        logging.info("❗ OPENAI_API_KEY is not set")
        return "Извините, сейчас сервер не настроен. Попробуйте позже."

    # История диалога для пользователя
    history = get_history(user_id)

    messages = [{"role": "system", "content": system_prompt}] + history

    try:
        completion = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=messages,
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
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
