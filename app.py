import os
import logging
import traceback
from flask import Flask, request
from telegram import Bot, Update
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters, CallbackContext
import openai

# -------------------------------------------------
# Logging setup
# -------------------------------------------------
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("scamshield")

# -------------------------------------------------
# Environment variables
# -------------------------------------------------
TG_TOKEN = os.environ.get("TG_BOT_TOKEN") or os.environ.get("TELEGRAM_TOKEN")
OPENAI_KEY = os.environ.get("OPENAI_API_KEY")

if not TG_TOKEN:
    logger.error("Missing Telegram token (TG_BOT_TOKEN or TELEGRAM_TOKEN).")
if not OPENAI_KEY:
    logger.error("Missing OpenAI API key (OPENAI_API_KEY).")

bot = Bot(token=TG_TOKEN)
openai.api_key = OPENAI_KEY

# -------------------------------------------------
# Flask app
# -------------------------------------------------
app = Flask(__name__)
dispatcher = Dispatcher(bot, None, workers=0, use_context=True)


# -------------------------------------------------
# Command Handlers
# -------------------------------------------------
def start(update: Update, context: CallbackContext):
    update.message.reply_text("👋 ScamShield AI is live and protecting you!")


def upgrade_cmd(update: Update, context: CallbackContext):
    update.message.reply_text("⚡ Upgrade feature coming soon!")


# -------------------------------------------------
# AI Message Handler
# -------------------------------------------------
def handle_message(update: Update, context: CallbackContext):
    text = update.message.text
    logger.info(f"User said: {text}")

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": text}],
        )
        reply = response.choices[0].message.content.strip()
    except Exception as e:
        logger.error("OpenAI error: %s", e)
        logger.error(traceback.format_exc())
        reply = f"⚠️ AI error: {e}"

    update.message.reply_text(reply)


# -------------------------------------------------
# Register Handlers
# -------------------------------------------------
dispatcher.add_handler(CommandHandler("start", start))
dispatcher.add_handler(CommandHandler("upgrade", upgrade_cmd))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))


# -------------------------------------------------
# Routes
# -------------------------------------------------
@app.route("/")
def home():
    return "ScamShield bot is running!"


@app.route(f"/webhook/{TG_TOKEN}", methods=["POST"])
def webhook():
    update = Update.de_json(request.get_json(force=True), bot)
    dispatcher.process_update(update)
    return "ok"


# Reset webhook manually if needed
@app.route("/reset", methods=["GET"])
def reset_webhook():
    bot.delete_webhook()
    success = bot.set_webhook(url=f"https://{os.environ.get('RENDER_EXTERNAL_HOSTNAME')}/webhook/{TG_TOKEN}")
    return f"Webhook reset: {success}"


# -------------------------------------------------
# Startup
# -------------------------------------------------
if __name__ == "__main__":
    url = f"https://{os.environ.get('RENDER_EXTERNAL_HOSTNAME')}/webhook/{TG_TOKEN}"
    bot.delete_webhook()
    success = bot.set_webhook(url=url)
    logger.info(f"Registering webhook to: {url} (success={success})")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
