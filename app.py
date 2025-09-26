# app.py  (webhook-only; compatible with python-telegram-bot v13.15)
import os
import logging
from flask import Flask, request, jsonify
from telegram import Bot, Update
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters
import openai

# -------- Logging --------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scamshield")

# -------- Config from environment --------
TOKEN = os.getenv("TELEGRAM_TOKEN") or os.getenv("TG_BOT_TOKEN")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
BASE_URL = os.getenv("BASE_URL")  # optional, recommended

if not TOKEN:
    logger.error("Missing TELEGRAM_TOKEN / TG_BOT_TOKEN env var.")
    raise SystemExit(1)
if not OPENAI_KEY:
    logger.error("Missing OPENAI_API_KEY env var.")
    raise SystemExit(1)

openai.api_key = OPENAI_KEY

# -------- Bot, Dispatcher, Flask --------
bot = Bot(token=TOKEN)
dispatcher = Dispatcher(bot, None, workers=4, use_context=True)
app = Flask(__name__)

# -------- Handlers --------
def start(update, context):
    update.message.reply_text("👋 ScamShield AI is live and protecting you!")

def help_cmd(update, context):
    update.message.reply_text("Commands: /start /help /upgrade — or just send a message to get AI help.")

def upgrade_cmd(update, context):
    update.message.reply_text("⚡ Upgrade: coming soon!")

def handle_message(update, context):
    user_text = update.message.text or ""
    try:
        resp = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are ScamShield. Give short, practical advice about whether a message is a scam."},
                {"role": "user", "content": user_text}
            ],
            temperature=0.0,
            max_tokens=200,
        )
        reply = resp["choices"][0]["message"]["content"].strip()
    except Exception:
        logger.exception("OpenAI error")
        reply = "Sorry — AI currently unavailable. Try again later."
    update.message.reply_text(reply)

dispatcher.add_handler(CommandHandler("start", start))
dispatcher.add_handler(CommandHandler("help", help_cmd))
dispatcher.add_handler(CommandHandler("upgrade", upgrade_cmd))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))

# -------- Webhook route (Telegram will POST updates here) --------
@app.route(f"/webhook/{TOKEN}", methods=["POST"])
def webhook():
    try:
        data = request.get_json(force=True)
        update = Update.de_json(data, bot)
        dispatcher.process_update(update)
        return jsonify({"status": "ok"}), 200
    except Exception:
        logger.exception("Failed processing update")
        return jsonify({"error": "failed"}), 500

@app.route("/")
def index():
    return "ScamShield webhook bot is running ✅", 200

# -------- Helper to compute and register webhook --------
def build_webhook_url():
    if BASE_URL:
        base = BASE_URL.rstrip("/")
    else:
        host = os.environ.get("RENDER_EXTERNAL_HOSTNAME") or os.environ.get("RENDER_EXTERNAL_URL")
        if not host:
            raise RuntimeError("Set BASE_URL env var or ensure RENDER_EXTERNAL_HOSTNAME/RENDER_EXTERNAL_URL is present.")
        if host.startswith("http://") or host.startswith("https://"):
            base = host.rstrip("/")
        else:
            base = f"https://{host.rstrip('/')}"
    return f"{base}/webhook/{TOKEN}"

def register_webhook():
    url = build_webhook_url()
    logger.info("Registering webhook to: %s", url)
    bot.delete_webhook()
    ok = bot.set_webhook(url=url)
    logger.info("bot.set_webhook returned: %s", ok)

# -------- Startup --------
if __name__ == "__main__":
    register_webhook()               # <-- important: register webhook on startup
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
