import logging
import os
import requests
from flask import Flask, request
from telegram import Bot, Update
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scamshield")

# Load token
TOKEN = os.environ.get("TG_BOT_TOKEN") or os.environ.get("TELEGRAM_TOKEN")
if not TOKEN:
    raise ValueError("No Telegram bot token found in environment variables!")

bot = Bot(token=TOKEN)

# Webhook URL (Render gives your app a public hostname automatically)
WEBHOOK_URL = f"https://{os.environ.get('RENDER_EXTERNAL_HOSTNAME')}/webhook/{TOKEN}"

# Flask app
app = Flask(__name__)

# === Register webhook on startup ===
def set_webhook():
    url = f"https://api.telegram.org/bot{TOKEN}/setWebhook?url={WEBHOOK_URL}"
    resp = requests.get(url)
    logger.info(f"Webhook set response: {resp.json()}")
    return resp.json()

set_webhook()  # call it once when app starts


# === Telegram Dispatcher ===
dispatcher = Dispatcher(bot, None, workers=0)

def start(update: Update, context):
    update.message.reply_text("🤖 Hello! ScamShield bot is active.")

def upgrade(update: Update, context):
    update.message.reply_text("⚡ Upgrade option coming soon.")

def handle_message(update: Update, context):
    text = update.message.text
    update.message.reply_text(f"✅ You said: {text}")


dispatcher.add_handler(CommandHandler("start", start))
dispatcher.add_handler(CommandHandler("upgrade", upgrade))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))


# === Webhook route ===
@app.route(f"/webhook/{TOKEN}", methods=["POST"])
def webhook():
    update = Update.de_json(request.get_json(force=True), bot)
    dispatcher.process_update(update)
    return "ok"


# === Reset webhook manually (optional helper) ===
@app.route("/reset-webhook", methods=["GET"])
def reset_webhook():
    requests.get(f"https://api.telegram.org/bot{TOKEN}/deleteWebhook")
    result = set_webhook()
    return {"status": "Webhook reset", "result": result}


# === Root check ===
@app.route("/", methods=["GET"])
def index():
    return "✅ ScamShield bot is running!"


# === Run ===
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
