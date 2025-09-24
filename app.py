import os
import logging
from flask import Flask, request
from telegram import Bot, Update
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters
from telegram.ext import CallbackContext

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Env vars
TOKEN = os.environ.get("TELEGRAM_TOKEN") or os.environ.get("TG_BOT_TOKEN")
OPENAI_KEY = os.environ.get("OPENAI_API_KEY")

if not TOKEN or not OPENAI_KEY:
    logger.error("Missing TELEGRAM_TOKEN/TG_BOT_TOKEN or OPENAI_API_KEY")
    exit(1)

# Flask app
app = Flask(__name__)

# Telegram bot
bot = Bot(token=TOKEN)
dispatcher = Dispatcher(bot, None, workers=4, use_context=True)

# Commands
def start(update: Update, context: CallbackContext):
    update.message.reply_text("👋 ScamShield AI is live and protecting you!")

def upgrade(update: Update, context: CallbackContext):
    update.message.reply_text("⚡ Upgrade feature coming soon!")

# Handlers
dispatcher.add_handler(CommandHandler("start", start))
dispatcher.add_handler(CommandHandler("upgrade", upgrade))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, lambda u, c: u.message.reply_text("✅ Message received!")))

# Webhook endpoint
@app.route(f"/webhook/{TOKEN}", methods=["POST"])
def webhook():
    update = Update.de_json(request.get_json(force=True), bot)
    dispatcher.process_update(update)
    return "ok", 200

# Health check
@app.route("/")
def index():
    return "ScamShield bot is running ✅", 200

# Set webhook at startup
with app.app_context():
    WEBHOOK_URL = f"https://{os.environ['RENDER_EXTERNAL_HOSTNAME']}/webhook/{TOKEN}"
    bot.delete_webhook()
    bot.set_webhook(url=WEBHOOK_URL)
    logger.info(f"Webhook set to {WEBHOOK_URL}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
