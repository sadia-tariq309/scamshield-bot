import os
import logging
from flask import Flask, request, jsonify
import telegram
from telegram.ext import Dispatcher, CommandHandler
import stripe

# ---------------- CONFIG ----------------
BOT_TOKEN = os.environ.get("BOT_TOKEN")
BASE_URL = os.environ.get("BASE_URL", "https://scamshield-bot-xxxxx.onrender.com")

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

bot = telegram.Bot(token=BOT_TOKEN)

# Stripe setup
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# In-memory DB (replace later with real DB)
user_db = {}

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scamshield")

# Flask app
app = Flask(__name__)

# ---------------- BOT COMMANDS ----------------
def cmd_start(update, context):
    update.message.reply_text("👋 Welcome to ScamShield Bot!\nUse /help to see commands.")

def cmd_help(update, context):
    update.message.reply_text(
        "ℹ️ Available commands:\n"
        "/start - Welcome message\n"
        "/help - Show this help\n"
        "/subscribe - Start subscription\n"
        "/upgrade - Upgrade to premium"
    )

def cmd_subscribe(update, context):
    update.message.reply_text(
        "💳 Use /upgrade to get a Premium plan with ScamShield."
    )

# ✅ NEW: Upgrade command
def cmd_upgrade(update, context):
    uid = update.message.from_user.id
    if not STRIPE_PRICE_ID or not STRIPE_SECRET_KEY:
        update.message.reply_text("⚠️ Payments are not configured right now.")
        return
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            mode="subscription",
            success_url=(BASE_URL.rstrip("/") if BASE_URL else "") + "/success",
            cancel_url=(BASE_URL.rstrip("/") if BASE_URL else "") + "/cancel",
            client_reference_id=str(uid),
        )
        update.message.reply_text(f"💳 Upgrade to Premium here:\n{session.url}")
    except Exception as e:
        logger.exception("Failed to create checkout session")
        update.message.reply_text(f"⚠️ Error creating payment link: {e}")

# ---------------- STRIPE WEBHOOK ----------------
@app.route("/stripe_webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        return str(e), 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        uid = session.get("client_reference_id")
        if uid:
            user_db[uid] = {"premium": True}
            bot.send_message(chat_id=uid, text="🎉 Your ScamShield Premium is active!")
    return "ok", 200

# ---------------- TELEGRAM HANDLER ----------------
dispatcher = Dispatcher(bot, None, workers=0)
dispatcher.add_handler(CommandHandler("start", cmd_start))
dispatcher.add_handler(CommandHandler("help", cmd_help))
dispatcher.add_handler(CommandHandler("subscribe", cmd_subscribe))
dispatcher.add_handler(CommandHandler("upgrade", cmd_upgrade))  # ✅ new

@app.route(f"/webhook/{BOT_TOKEN}", methods=["POST"])
def webhook():
    update = telegram.Update.de_json(request.get_json(force=True), bot)
    dispatcher.process_update(update)
    return "ok"

@app.route("/", methods=["GET"])
def index():
    return "✅ ScamShield Bot is running."

# ---------------- STARTUP ----------------
if __name__ == "__main__":
    url = f"{BASE_URL}/webhook/{BOT_TOKEN}"
    bot.delete_webhook()
    bot.set_webhook(url)
    logger.info(f"Webhook set to {url}")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
