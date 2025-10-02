# app.py
# Complete: Telegram webhook bot + promo codes + Stripe checkout (test-ready) + usage limits + users.json storage

import os
import json
import logging
import sqlite3
import traceback
from datetime import datetime, date, timedelta
from flask import Flask, request, jsonify, redirect
import stripe
import telegram
from telegram import Update, ParseMode, Bot
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters

# -------------- Logging --------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scamshield")

# -------------- Config / Env --------------
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
if not TELEGRAM_TOKEN:
    logger.error("Missing TELEGRAM_TOKEN env var. Set it in Render.")
    raise SystemExit("Missing TELEGRAM_TOKEN")

BASE_URL = os.getenv("BASE_URL")  # e.g. https://scamshield-bot-xxxxx.onrender.com
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
DAILY_LIMIT = int(os.getenv("DAILY_LIMIT", "10"))
ADMIN_IDS = [x.strip() for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()]

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# -------------- Files and storage --------------
USERS_FILE = "users.json"          # stores premium expiry per user
USAGE_FILE = "usage.json"          # daily usage counts
PROMO_FILE = "promo_codes.json"    # promo codes mapping to days

def load_json_file(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_json_file(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# ensure promo file exists (safe default if not present)
if not os.path.exists(PROMO_FILE):
    sample = {
        "FREE30": {"days": 30, "description": "30 days free premium"},
        "TEST7": {"days": 7, "description": "7 days free"}
    }
    save_json_file(PROMO_FILE, sample)

# -------------- User/premium helpers --------------
def get_users():
    return load_json_file(USERS_FILE)

def save_users(users):
    save_json_file(USERS_FILE, users)

def set_premium(telegram_id, days=30):
    users = get_users()
    uid = str(telegram_id)
    now = datetime.utcnow()
    current_exp = None
    if uid in users and users[uid].get("premium_until"):
        try:
            current_exp = datetime.fromisoformat(users[uid]["premium_until"])
        except Exception:
            current_exp = None
    if current_exp and current_exp > now:
        new_exp = current_exp + timedelta(days=days)
    else:
        new_exp = now + timedelta(days=days)
    users[uid] = {"premium_until": new_exp.isoformat()}
    save_users(users)
    logger.info("Set premium for %s until %s", uid, new_exp.isoformat())

def is_premium(telegram_id):
    users = get_users()
    uid = str(telegram_id)
    entry = users.get(uid)
    if not entry:
        return False
    exp = entry.get("premium_until")
    if not exp:
        return False
    try:
        return datetime.fromisoformat(exp) > datetime.utcnow()
    except Exception:
        return False

# -------------- Usage (daily limits) --------------
def get_usage():
    return load_json_file(USAGE_FILE)

def save_usage(data):
    save_json_file(USAGE_FILE, data)

def check_and_increment_usage(user_id):
    if is_premium(user_id):
        return True, None
    data = get_usage()
    key = str(user_id)
    today = date.today().isoformat()
    entry = data.get(key, {"date": today, "count": 0})
    if entry.get("date") != today:
        entry = {"date": today, "count": 0}
    if entry["count"] >= DAILY_LIMIT:
        data[key] = entry
        save_usage(data)
        return False, entry["count"]
    entry["count"] += 1
    data[key] = entry
    save_usage(data)
    return True, entry["count"]

# -------------- Promo codes --------------
def load_promos():
    return load_json_file(PROMO_FILE)

def redeem_code(user_id, code):
    promos = load_promos()
    c = code.upper()
    if c not in promos:
        return False, "Invalid or expired promo code."
    try:
        days = int(promos[c].get("days", 30))
    except Exception:
        days = 30
    set_premium(user_id, days=days)
    desc = promos[c].get("description", f"{days} days premium")
    return True, f"🎉 Promo applied: {desc} ({days} days)."

# -------------- Scam detector (simple rule-based) --------------
SUSPICIOUS_KEYWORDS = [
    "wire transfer", "western union", "bank transfer", "send money",
    "urgent", "act now", "verify your account", "click the link",
    "limited time", "winner", "congratulations", "prize", "lottery",
    "claim now", "password", "account suspended", "deposit", "loan"
]

def analyze_text_simple(text):
    txt = (text or "").lower()
    reasons = []
    score = 0
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in txt:
            score += 20
            reasons.append(f"Contains '{kw}'")
    if "http://" in txt or "https://" in txt:
        score += 15
        reasons.append("Contains URL")
    if "$" in txt or "usd" in txt:
        score += 10
        reasons.append("Money mentioned")
    score = min(100, score)
    if score >= 60:
        verdict = "High"
        advice = "Do NOT click links or reply. Verify independently."
    elif score >= 30:
        verdict = "Medium"
        advice = "Be cautious — verify sender and links."
    else:
        verdict = "Low"
        advice = "Appears low risk, but always verify."
    return {"verdict": verdict, "score": score, "reasons": reasons[:6], "advice": advice}

# -------------- Telegram bot & Flask --------------
bot = Bot(token=TELEGRAM_TOKEN)
dispatcher = Dispatcher(bot, None, workers=4, use_context=True)
app = Flask(__name__)

# -------------- Command handlers --------------
def cmd_start(update, context):
    uid = update.message.from_user.id
    sub = f"{BASE_URL.rstrip('/')}/subscribe?telegram_id={uid}" if BASE_URL else "https://<your-url>/subscribe"
    text = (
        "👋 ScamShield AI — paste a suspicious message and I'll check it.\n\n"
        f"Free users: {DAILY_LIMIT}/day. Upgrade for unlimited checks.\n\n"
        f"Subscribe (checkout): {sub}\n"
        "Use /upgrade for one-step checkout, /redeem CODE to use a promo, /status to check plan."
    )
    update.message.reply_text(text)

def cmd_status(update, context):
    uid = update.message.from_user.id
    if is_premium(uid):
        update.message.reply_text("🎉 You are PREMIUM — unlimited checks.")
    else:
        update.message.reply_text(f"Free user — {DAILY_LIMIT} checks/day. Use /upgrade or /redeem CODE.")

def cmd_upgrade(update, context):
    uid = update.message.from_user.id
    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID:
        update.message.reply_text("⚠️ Payments are not configured. Admin needs to set Stripe keys.")
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
        update.message.reply_text(f"💳 Upgrade to Premium via this secure link:\n{session.url}")
    except Exception as e:
        logger.exception("Stripe checkout create failed")
        update.message.reply_text(f"⚠️ Payment link error: {e}")

def cmd_redeem(update, context):
    uid = update.message.from_user.id
    args = context.args or []
    if not args:
        update.message.reply_text("Usage: /redeem CODE")
        return
    code = args[0].strip()
    ok, msg = redeem_code(uid, code)
    update.message.reply_text(msg)

def cmd_grant(update, context):
    sender = str(update.message.from_user.id)
    if sender not in ADMIN_IDS:
        update.message.reply_text("❌ You are not authorized to use this command.")
        return
    args = context.args or []
    if not args:
        update.message.reply_text("Usage: /grant <telegram_id> [days]")
        return
    tg = args[0].strip()
    days = int(args[1]) if len(args) > 1 else 30
    try:
        set_premium(tg, days=days)
        update.message.reply_text(f"✅ Granted {days} days premium to {tg}.")
        try:
            bot.send_message(chat_id=int(tg), text=f"🎉 An admin granted you {days} days Premium.")
        except Exception:
            pass
    except Exception as e:
        logger.exception("grant failed")
        update.message.reply_text(f"Error granting premium: {e}")

def handle_message(update, context):
    try:
        uid = update.message.from_user.id
        text = (update.message.text or "").strip()
        if not text:
            update.message.reply_text("Please send some text to analyze.")
            return

        ok, count = check_and_increment_usage(uid)
        if not ok:
            update.message.reply_text(f"Daily limit reached ({DAILY_LIMIT}). Use /upgrade or /redeem CODE.")
            return

        result = analyze_text_simple(text)
        reply = f"{'⚠️' if result['verdict']=='High' else '❗' if result['verdict']=='Medium' else '✅'} *Verdict:* *{result['verdict']}* _(score: {result['score']}/100)_\n\n"
        if result['reasons']:
            reply += "*Top flags:*\n"
            for r in result['reasons']:
                reply += f"• {r}\n"
        reply += f"\n*Advice:* {result['advice']}"
        update.message.reply_text(reply, parse_mode=ParseMode.MARKDOWN)
    except Exception:
        logger.exception("handle_message failed")
        update.message.reply_text("⚠️ An error occurred while analyzing. Try again later.")

# register handlers
dispatcher.add_handler(CommandHandler("start", cmd_start))
dispatcher.add_handler(CommandHandler("status", cmd_status))
dispatcher.add_handler(CommandHandler("upgrade", cmd_upgrade))
dispatcher.add_handler(CommandHandler("redeem", cmd_redeem))
dispatcher.add_handler(CommandHandler("grant", cmd_grant))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))

# -------------- Webhook helpers --------------
def build_webhook_url():
    if BASE_URL:
        base = BASE_URL.rstrip("/")
        if not base.startswith("http"):
            base = "https://" + base
    else:
        host = os.environ.get("RENDER_EXTERNAL_HOSTNAME") or os.environ.get("RENDER_EXTERNAL_URL")
        if not host:
            raise RuntimeError("Set BASE_URL env var or ensure RENDER_EXTERNAL_HOSTNAME/RENDER_EXTERNAL_URL is present.")
        base = ("https://" + host) if not host.startswith("http") else host
        base = base.rstrip("/")
    return f"{base}/webhook/{TELEGRAM_TOKEN}"

def register_webhook():
    try:
        url = build_webhook_url()
        logger.info("Registering Telegram webhook: %s", url)
        bot.delete_webhook()
        ok = bot.set_webhook(url=url)
        logger.info("set_webhook result: %s", ok)
    except Exception:
        logger.exception("Failed to register webhook")
        raise

# -------------- Stripe endpoints --------------
@app.route("/subscribe", methods=["GET"])
def subscribe():
    tg = request.args.get("telegram_id")
    if not STRIPE_PRICE_ID or not STRIPE_SECRET_KEY:
        return "Stripe not configured", 500
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            mode="subscription",
            success_url=(BASE_URL.rstrip("/") if BASE_URL else "") + "/success",
            cancel_url=(BASE_URL.rstrip("/") if BASE_URL else "") + "/cancel",
            client_reference_id=str(tg) if tg else None,
        )
        return redirect(session.url, code=302)
    except Exception as e:
        logger.exception("create checkout failed")
        return f"Stripe error: {e}", 500

@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    if not STRIPE_WEBHOOK_SECRET:
        logger.error("STRIPE_WEBHOOK_SECRET not configured")
        return "Missing webhook secret", 500
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception:
        logger.exception("Invalid Stripe signature")
        return "Invalid signature", 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        tg = session.get("client_reference_id")
        logger.info("Stripe checkout completed, client_reference_id=%s", tg)
        if tg:
            set_premium(tg, days=30)
            try:
                bot.send_message(chat_id=int(tg), text="🎉 Thank you — your subscription is active! You are now Premium.")
            except Exception:
                logger.exception("Failed to notify user via Telegram")
    elif event["type"] == "invoice.payment_failed":
        session = event["data"]["object"]
        tg = session.get("client_reference_id")
        if tg:
            try:
                bot.send_message(chat_id=int(tg), text="⚠️ We couldn't process your payment. Please update payment method.")
            except Exception:
                logger.exception("Failed to notify user of failed payment")

    return jsonify({"ok": True})

# -------------- Telegram webhook route --------------
@app.route(f"/webhook/{TELEGRAM_TOKEN}", methods=["POST"])
def telegram_webhook():
    try:
        data = request.get_json(force=True)
        update = Update.de_json(data, bot)
        dispatcher.process_update(update)
        return jsonify({"ok": True})
    except Exception:
        logger.exception("Failed to process telegram update")
        return jsonify({"ok": False}), 500

# -------------- Start --------------
if __name__ == "__main__":
    register_webhook()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
