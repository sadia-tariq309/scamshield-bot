import os
import json
import logging
import stripe
import telegram
from telegram.ext import (
    Application, CommandHandler, MessageHandler, filters
)
from flask import Flask, request

# ---------------- Logging ---------------- #
logging.basicConfig(level=logging.INFO)

# ---------------- Env Vars ---------------- #
BOT_TOKEN = os.getenv("TELEGRAM_TOKEN")
STRIPE_SECRET_KEY = os.getenv("Stripe_secret_key")
STRIPE_PRICE_ID = os.getenv("Stripe_price_ID")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
BASE_URL = os.getenv("BASE_URL")
ADMIN_IDS = os.getenv("ADMIN_IDS", "").split(",")

if not BOT_TOKEN:
    raise ValueError("❌ TELEGRAM_TOKEN missing in Render environment")

if not STRIPE_SECRET_KEY:
    raise ValueError("❌ Stripe_secret_key missing in Render environment")

# ---------------- Telegram Bot ---------------- #
bot = telegram.Bot(token=BOT_TOKEN)

# ---------------- Flask for Stripe Webhook ---------------- #
app = Flask(__name__)
stripe.api_key = STRIPE_SECRET_KEY

# ---------------- Promo Codes ---------------- #
PROMO_CODES_FILE = "promo_codes.json"

if not os.path.exists(PROMO_CODES_FILE):
    with open(PROMO_CODES_FILE, "w") as f:
        json.dump({"FREE30": {"days": 30}}, f)

with open(PROMO_CODES_FILE) as f:
    PROMO_CODES = json.load(f)


# ---------------- Handlers ---------------- #
async def start(update, context):
    await update.message.reply_text(
        "👋 ScamShield AI — paste a suspicious message and I'll check it.\n\n"
        "Free users: 10/day. Upgrade for unlimited checks.\n\n"
        f"Subscribe: {BASE_URL}/subscribe?telegram_id={update.message.from_user.id}\n\n"
        "Use /upgrade for one-step checkout, or /status to see your plan."
    )


async def upgrade(update, context):
    try:
        checkout = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            success_url=f"{BASE_URL}/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}/cancel",
            metadata={"telegram_id": update.message.from_user.id}
        )
        await update.message.reply_text(f"💳 Upgrade here: {checkout.url}")
    except Exception as e:
        await update.message.reply_text(f"⚠️ Payment link error: {str(e)}")


async def redeem(update, context):
    if len(context.args) != 1:
        await update.message.reply_text("❌ Usage: /redeem CODE")
        return

    code = context.args[0].upper()
    if code in PROMO_CODES:
        days = PROMO_CODES[code]["days"]
        await update.message.reply_text(f"✅ Promo code applied! {days} days premium unlocked.")
    else:
        await update.message.reply_text("❌ Invalid promo code.")


# ---------------- Flask Route ---------------- #
@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        return {"error": str(e)}, 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        telegram_id = session["metadata"]["telegram_id"]
        bot.send_message(chat_id=telegram_id, text="🎉 Payment successful! Premium activated.")

    return {"status": "ok"}


# ---------------- Main ---------------- #
def main():
    application = Application.builder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("upgrade", upgrade))
    application.add_handler(CommandHandler("redeem", redeem))

    application.run_polling()


if __name__ == "__main__":
    import threading

    threading.Thread(target=lambda: app.run(host="0.0.0.0", port=5000)).start()
    main()
