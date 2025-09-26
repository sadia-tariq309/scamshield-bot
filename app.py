import os
import logging
from flask import Flask, request
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext, Dispatcher
import openai

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scamshield")

# === ENV VARS ===
BOT_TOKEN = os.environ.get("TG_BOT_TOKEN") or os.environ.get("TELEGRAM_TOKEN")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

if not BOT_TOKEN or not OPENAI_API_KEY:
    logger.error("Missing env vars: TG_BOT_TOKEN / TELEGRAM_TOKEN, OPENAI_API_KEY")
    raise SystemExit("❌ Missing required environment variables.")

openai.api_key = OPENAI_API_KEY

# === Flask App ===
app = Flask(__name__)

# === Telegram Bot Setup ===
updater = Updater(token=BOT_TOKEN, use_context=True)
dispatcher: Dispatcher = updater.dispatcher

# === Handlers ===
def start(update: Update, context: CallbackContext):
    update.message.reply_text("👋 Hi! I’m ScamShield AI. Send me any message and I’ll check if it looks suspicious or just chat with you smartly.")

def upgrade(update: Update, context: CallbackContext):
    update.message.reply_text("⚡ Upgrade feature coming soon! (Stripe config needed).")

def handle_message(update: Update, context: CallbackContext):
    user_message = update.message.text
    try:
        # Call OpenAI for AI response
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are ScamShield AI, a helpful assistant that warns about scams and also chats like a smart friend."},
                {"role": "user", "content": user_message}
            ]
        )
        ai_reply = response["choices"][0]["message"]["content"]
    except Exception as e:
        logger.error(f"OpenAI error: {e}")
        ai_reply = "⚠️ Sorry, I had trouble connecting to AI. Try again later."

    context.bot.send_message(chat_id=update.effective_chat.id, text=ai_reply)

# Register commands & handlers
dispatcher.add_handler(CommandHandler("start", start))
dispatcher.add_handler(CommandHandler("upgrade", upgrade))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))

# === Webhook Routes ===
@app.route("/")
def home():
    return "✅ ScamShield AI bot is running!"

@app.route(f"/webhook/{BOT_TOKEN}", methods=["POST"])
def webhook():
    update = Update.de_json(request.get_json(force=True), updater.bot)
    dispatcher.process_update(update)
    return "OK", 200

# === Set webhook on startup ===
@app.before_first_request
def register_webhook():
    webhook_url = f"https://{os.environ['RENDER_EXTERNAL_HOSTNAME']}/webhook/{BOT_TOKEN}"
    success = updater.bot.set_webhook(webhook_url)
    logger.info(f"Registering webhook to: {webhook_url}")
    logger.info(f"bot.set_webhook returned: {success}")

# === Run Flask App ===
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
