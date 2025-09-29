import os
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, request
import telegram

# ================== CONFIG ==================
BOT_TOKEN = os.environ.get("BOT_TOKEN")
BASE_URL = os.environ.get("BASE_URL")  # e.g. https://scamshield-bot.onrender.com
ADMIN_IDS = os.environ.get("ADMIN_IDS", "")  # comma separated IDs

if not BOT_TOKEN:
    raise ValueError("❌ BOT_TOKEN missing in Render environment")

bot = telegram.Bot(token=BOT_TOKEN)
app = Flask(__name__)

# ================== FILE HELPERS ==================
USERS_FILE = "users.json"
PROMO_FILE = "promo_codes.json"

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def load_promos():
    if os.path.exists(PROMO_FILE):
        with open(PROMO_FILE, "r") as f:
            return json.load(f)
    return {}

# ================== USER PREMIUM ==================
def is_premium(user_id):
    users = load_users()
    user = users.get(str(user_id), {})
    exp = user.get("premium_until")
    if exp:
        return datetime.fromisoformat(exp) > datetime.utcnow()
    return False

def add_premium(user_id, days):
    users = load_users()
    uid = str(user_id)
    now = datetime.utcnow()
    exp = now + timedelta(days=days)

    if uid in users and users[uid].get("premium_until"):
        old_exp = datetime.fromisoformat(users[uid]["premium_until"])
        if old_exp > now:
            exp = old_exp + timedelta(days=days)

    users[uid] = {"premium_until": exp.isoformat()}
    save_users(users)

# ================== COMMAND HANDLERS ==================
def handle_start(chat_id):
    bot.send_message(
        chat_id=chat_id,
        text="👋 Welcome to ScamShield Bot!\nSend me any message and I'll analyze it.\n\n"
             "Use /upgrade to get premium features.\nUse /redeem CODE if you have a promo code."
    )

def handle_upgrade(chat_id):
    bot.send_message(
        chat_id=chat_id,
        text="💎 To upgrade, please use a promo code (/redeem CODE)."
    )

def handle_redeem(chat_id, code):
    promos = load_promos()
    code_data = promos.get(code.upper())

    if not code_data:
        bot.send_message(chat_id=chat_id, text="❌ Invalid promo code.")
        return

    add_premium(chat_id, code_data["days"])
    bot.send_message(
        chat_id=chat_id,
        text=f"✅ Promo applied: {code_data['description']}.\n"
             f"Enjoy {code_data['days']} days of premium!"
    )

# ================== FLASK WEBHOOK ==================
@app.route(f"/webhook/{BOT_TOKEN}", methods=["POST"])
def webhook():
    update = telegram.Update.de_json(request.get_json(force=True), bot)

    if update.message:
        chat_id = update.message.chat_id
        text = update.message.text or ""

        if text.startswith("/start"):
            handle_start(chat_id)
        elif text.startswith("/upgrade"):
            handle_upgrade(chat_id)
        elif text.startswith("/redeem"):
            parts = text.split()
            if len(parts) > 1:
                handle_redeem(chat_id, parts[1])
            else:
                bot.send_message(chat_id=chat_id, text="⚠️ Usage: /redeem CODE")
        else:
            if is_premium(chat_id):
                bot.send_message(chat_id=chat_id, text=f"🔎 Scam analysis result for:\n{text}\n\n✅ Safe.")
            else:
                bot.send_message(chat_id=chat_id, text="⚠️ You need premium to analyze messages.\nUse /upgrade.")
    return "ok"

@app.route("/")
def home():
    return "✅ ScamShield Bot is running!"

# ================== STARTUP ==================
if __name__ == "__main__":
    # Register webhook each start
    url = f"{BASE_URL}/webhook/{BOT_TOKEN}"
    bot.set_webhook(url)
    logging.info(f"Webhook set to {url}")
    app.run(host="0.0.0.0", port=10000)
