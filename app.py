import os
import json
import time
import logging
from flask import Flask, request, jsonify, abort
import telegram
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters
import stripe

# ---------------- CONFIG ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN")
BASE_URL = os.getenv("BASE_URL")  # e.g. https://your-bot.onrender.com
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
ADMIN_IDS = os.getenv("ADMIN_IDS", "")  # e.g. "123456789,987654321"
ADMIN_IDS = set(i.strip() for i in ADMIN_IDS.split(",") if i.strip())

PROMO_FILE = "promo_codes.json"
USERS_FILE = "users.json"

# Stripe init
stripe.api_key = STRIPE_SECRET_KEY

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask + Telegram bot
app = Flask(__name__)
bot = telegram.Bot(token=BOT_TOKEN)
dispatcher = Dispatcher(bot, None, workers=0)

# ---------------- UTILITIES ----------------
def load_users():
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

def load_promos():
    try:
        with open(PROMO_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_promos(d):
    with open(PROMO_FILE, "w") as f:
        json.dump(d, f)

def is_premium(user_id):
    users = load_users()
    data = users.get(str(user_id))
    if not data:
        return False
    expiry = data.get("expiry", 0)
    return time.time() < expiry

def set_premium(user_id, days=30):
    users = load_users()
    expiry = time.time() + days * 86400
    users[str(user_id)] = {"expiry": expiry}
    save_users(users)

# ---------------- BOT COMMANDS ----------------
def start(update, context):
    update.message.reply_text(
        "👋 Welcome to ScamShield AI!\n\n"
        "Send me any suspicious message and I’ll check if it looks like a scam.\n\n"
        "Free users: 10 checks/day.\n"
        "Upgrade to Premium for unlimited checks → /upgrade"
    )

def status(update, context):
    uid = update.message.from_user.id
    if is_premium(uid):
        update.message.reply_text("✅ You are a PREMIUM user.")
    else:
        update.message.reply_text("ℹ️ You are a FREE user. Use /upgrade to unlock unlimited checks.")

def upgrade(update, context):
    uid = update.message.from_user.id
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            mode="subscription",
            success_url=f"{BASE_URL}/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}/cancel",
            metadata={"telegram_id": uid},
        )
        update.message.reply_text(
            f"💳 Upgrade to Premium:\n\nClick here to subscribe:\n{session.url}"
        )
    except Exception as e:
        logger.exception("Stripe error")
        update.message.reply_text("⚠️ Payment error. Try again later.")

def redeem(update, context):
    uid = update.message.from_user.id
    args = context.args or []
    if len(args) == 0:
        update.message.reply_text("Usage: /redeem CODE")
        return
    code = args[0].strip().upper()
    promos = load_promos()
    entry = promos.get(code)
    if not entry or entry.get("uses", 0) <= 0:
        update.message.reply_text("❌ Invalid or expired promo code.")
        return
    set_premium(uid, days=30)
    entry["uses"] = entry.get("uses", 1) - 1
    promos[code] = entry
    save_promos(promos)
    update.message.reply_text("🎉 Promo accepted — you are PREMIUM for 30 days!")

def grant(update, context):
    sender = str(update.message.from_user.id)
    if sender not in ADMIN_IDS:
        update.message.reply_text("❌ You are not authorized.")
        return
    args = context.args or []
    if not args:
        update.message.reply_text("Usage: /grant <telegram_id> [days]")
        return
    tg = args[0].strip()
    days = int(args[1]) if len(args) > 1 else 30
    set_premium(tg, days=days)
    update.message.reply_text(f"✅ Granted {days} days premium to {tg}.")
    try:
        bot.send_message(chat_id=int(tg), text=f"🎉 You were granted {days} days Premium!")
    except Exception:
        pass

def handle_message(update, context):
    uid = update.message.from_user.id
    text = update.message.text

    if not is_premium(uid):
        users = load_users()
        data = users.get(str(uid), {"count": 0, "reset": time.time()})
        # Reset daily
        if time.time() - data.get("reset", 0) > 86400:
            data["count"] = 0
            data["reset"] = time.time()
        if data["count"] >= 10:
            update.message.reply_text("🚫 Daily limit reached. Use /upgrade or /redeem a code.")
            return
        data["count"] += 1
        users[str(uid)] = data
        save_users(users)

    scam_keywords = ["lottery", "prize", "click here", "bank account", "urgent"]
    if any(word in text.lower() for word in scam_keywords):
        update.message.reply_text("⚠️ This message looks suspicious. Be careful!")
    else:
        update.message.reply_text("✅ No scam detected in this message.")

# ---------------- WEBHOOK ROUTES ----------------
@app.route(f"/{BOT_TOKEN}", methods=["POST"])
def webhook():
    update = telegram.Update.de_json(request.get_json(force=True), bot)
    dispatcher.process_update(update)
    return "ok"

@app.route("/set_webhook", methods=["GET"])
def set_webhook():
    url = f"{BASE_URL}/{BOT_TOKEN}"
    bot.set_webhook(url)
    return f"Webhook set to {url}"

@app.route("/stripe_webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        logger.exception("Invalid webhook")
        return "Invalid", 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        tg = session["metadata"].get("telegram_id")
        if tg:
            set_premium(tg, days=30)
            try:
                bot.send_message(chat_id=int(tg), text="🎉 Payment successful! You are now PREMIUM.")
            except Exception:
                pass
    return "ok"

# ---------------- REGISTER HANDLERS ----------------
dispatcher.add_handler(CommandHandler("start", start))
dispatcher.add_handler(CommandHandler("status", status))
dispatcher.add_handler(CommandHandler("upgrade", upgrade))
dispatcher.add_handler(CommandHandler("redeem", redeem, pass_args=True))
dispatcher.add_handler(CommandHandler("grant", grant, pass_args=True))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
