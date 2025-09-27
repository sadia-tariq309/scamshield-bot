# app.py
# Complete ScamShield bot: Telegram webhook + rule-based scanner + OpenAI fallback
# + Stripe Checkout (/upgrade) with client_reference_id -> marks Telegram user premium.
# Uses SQLite for premium storage and JSON for daily usage counts.

import os
import re
import json
import logging
import sqlite3
import traceback
from datetime import datetime, date, timedelta
from flask import Flask, request, jsonify, redirect
import stripe
import openai
from telegram import Bot, Update, ParseMode
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters

# ---------------- logging ----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scamshield")

# ---------------- env (accept some name variants) ----------------
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN") or os.getenv("TG_BOT_TOKEN") or os.getenv("BOT_TOKEN")
if not TELEGRAM_TOKEN:
    logger.error("Missing TELEGRAM_TOKEN (set in Render environment).")
    raise SystemExit("Missing TELEGRAM_TOKEN")

BASE_URL = os.getenv("BASE_URL") or os.getenv("RENDER_EXTERNAL_URL") or os.getenv("RENDER_EXTERNAL_HOSTNAME")
# if RENDER provides only hostname, ensure https prefix when used later

OPENAI_KEY = os.getenv("OPENAI_API_KEY")
DAILY_LIMIT = int(os.getenv("DAILY_LIMIT", "10"))

# Stripe env (support both lower/upper from your screenshot)
STRIPE_SECRET_KEY = os.getenv("Stripe_secret_key") or os.getenv("STRIPE_SECRET_KEY") or os.getenv("STRIPE_SECRET")
STRIPE_PRICE_ID = os.getenv("Stripe_price_ID") or os.getenv("STRIPE_PRICE_ID") or os.getenv("STRIPE_PRICE")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET") or os.getenv("Stripe_webhook_secret")

if OPENAI_KEY:
    openai.api_key = OPENAI_KEY
else:
    logger.info("OPENAI_API_KEY not set — OpenAI fallback disabled (OK).")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
else:
    logger.info("Stripe not configured — /upgrade will show an error until keys are set.")

# ---------------- storage ----------------
DB_FILE = "scamshield_users.db"
USAGE_FILE = "usage_counts.json"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            telegram_id TEXT PRIMARY KEY,
            is_premium INTEGER DEFAULT 0,
            premium_until TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def set_premium(telegram_id, days=30):
    until = (datetime.utcnow() + timedelta(days=days)).isoformat()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO users (telegram_id, is_premium, premium_until)
        VALUES (?, 1, ?)
        ON CONFLICT(telegram_id) DO UPDATE SET is_premium=1, premium_until=excluded.premium_until
    """, (str(telegram_id), until))
    conn.commit()
    conn.close()
    logger.info("Set premium for %s until %s", telegram_id, until)

def is_premium(telegram_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT is_premium, premium_until FROM users WHERE telegram_id=?", (str(telegram_id),))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False
    is_p, premium_until = row
    if is_p and premium_until:
        try:
            return datetime.fromisoformat(premium_until) > datetime.utcnow()
        except Exception:
            return bool(is_p)
    return bool(is_p)

def load_usage():
    try:
        with open(USAGE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_usage(data):
    try:
        with open(USAGE_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        logger.exception("save_usage failed: %s", e)

def check_and_increment_usage(user_id):
    # Premium users bypass limits
    if is_premium(user_id):
        return True, None
    data = load_usage()
    today = date.today().isoformat()
    key = str(user_id)
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

# ---------------- rule-based scanner ----------------
SUSPICIOUS_KEYWORDS = [
    r"wire transfer", r"western union", r"bank transfer", r"send money",
    r"urgent", r"act now", r"verify your account", r"click the link",
    r"limited time", r"winner", r"congratulations", r"prize", r"lottery",
    r"claim now", r"password", r"account suspended", r"deposit", r"loan",
    r"final notice", r"verify identity"
]
URL_SHORTENERS = r"(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|tiny\.cc|is\.gd|buff\.ly)"

def analyze_text_rule_based(text):
    score = 0
    reasons = []
    low = text.lower()

    for kw in SUSPICIOUS_KEYWORDS:
        if re.search(kw, low):
            score += 18
            reasons.append(f"Suspicious phrase: '{kw}'")

    urls = re.findall(r"https?://[^\s]+", text)
    if urls:
        score += 12
        reasons.append(f"URL(s): {', '.join(urls)[:200]}")
        if re.search(URL_SHORTENERS, " ".join(urls), re.I):
            score += 25
            reasons.append("Shortened URL detected")

    if re.search(r"\$\s?\d{2,}", text) or re.search(r"\d+\s?USD", text, re.I):
        score += 12
        reasons.append("Mentions money")

    if re.search(r"!!+|!!!", text):
        score += 8
        reasons.append("Urgent punctuation")

    if sum(1 for c in text if c.isupper()) > max(6, int(len(text)*0.12)):
        score += 6
        reasons.append("Many uppercase characters")

    score = min(100, int(score))
    if score >= 60:
        verdict = "High"
        advice = "Do NOT click links or reply. Verify with official channels."
    elif score >= 30:
        verdict = "Medium"
        advice = "Be cautious — check sender identity and links before interacting."
    else:
        verdict = "Low"
        advice = "Appears low risk, but always verify."

    return {
        "verdict": verdict,
        "score": score,
        "reasons": reasons[:8],
        "advice": advice,
        "explain": f"Rule-based score {score}/100",
        "share_text": f"{verdict} ({score}/100) — {advice}"
    }

# ---------------- OpenAI fallback ----------------
AMBIGUOUS_LOW = 15
AMBIGUOUS_HIGH = 60

def analyze_with_openai(text):
    if not OPENAI_KEY:
        return {"error": "no_openai", "message": "OpenAI API key not configured."}
    try:
        resp = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are ScamShield: short, precise scam detection."},
                {"role": "user", "content": f"Analyze for scams and return a short verdict, 3 reasons and a one-line advice:\n\n{text}"}
            ],
            temperature=0.0,
            max_tokens=300,
        )
        return {"ok": True, "raw": resp["choices"][0]["message"]["content"].strip()}
    except Exception as e:
        logger.error("OpenAI error: %s", e)
        logger.error(traceback.format_exc())
        return {"error": "openai_error", "message": str(e)}

# ---------------- Telegram & Flask ----------------
bot = Bot(token=TELEGRAM_TOKEN)
dispatcher = Dispatcher(bot, None, workers=4, use_context=True)
app = Flask(__name__)

# helpers
def build_webhook_url():
    if BASE_URL:
        base = BASE_URL.rstrip("/")
        if not base.startswith("http"):
            base = "https://" + base
    else:
        host = os.environ.get("RENDER_EXTERNAL_HOSTNAME") or os.environ.get("RENDER_EXTERNAL_URL")
        if not host:
            raise RuntimeError("Set BASE_URL env var or ensure RENDER_EXTERNAL_HOSTNAME/RENDER_EXTERNAL_URL present.")
        base = ("https://" + host) if not host.startswith("http") else host
        base = base.rstrip("/")
    return f"{base}/webhook/{TELEGRAM_TOKEN}"

def register_webhook():
    try:
        url = build_webhook_url()
        logger.info("Registering webhook: %s", url)
        bot.delete_webhook()
        ok = bot.set_webhook(url=url)
        logger.info("set_webhook result: %s", ok)
    except Exception:
        logger.exception("Failed to register webhook")
        raise

# command handlers
def cmd_start(update, context):
    uid = update.message.from_user.id
    sub_link = f"{(BASE_URL.rstrip('/') if BASE_URL else '')}/subscribe?telegram_id={uid}"
    text = ("👋 ScamShield AI — paste a suspicious message and I'll check it.\n"
            f"Free users: {DAILY_LIMIT}/day. Upgrade for unlimited checks.\n\n"
            f"Subscribe (secure): {sub_link}\n\n"
            "Use /upgrade for a one-step checkout link, or /status to see your plan.")
    update.message.reply_text(text)

def cmd_help(update, context):
    update.message.reply_text("Send any text and I will analyze it. Commands: /start /help /upgrade /status")

def cmd_status(update, context):
    uid = update.message.from_user.id
    if is_premium(uid):
        update.message.reply_text("🎉 You are PREMIUM — unlimited checks.")
    else:
        update.message.reply_text(f"Free user — {DAILY_LIMIT} checks/day. Use /upgrade to subscribe.")

# /upgrade creates Stripe Checkout and returns session URL
def cmd_upgrade(update, context):
    uid = update.message.from_user.id
    if not STRIPE_PRICE_ID or not STRIPE_SECRET_KEY:
        update.message.reply_text("⚠️ Upgrade not configured. Contact admin.")
        return
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            mode="subscription",  # or 'payment' for one-time
            success_url=(BASE_URL.rstrip("/") if BASE_URL else "") + "/success",
            cancel_url=(BASE_URL.rstrip("/") if BASE_URL else "") + "/cancel",
            client_reference_id=str(uid),
        )
        update.message.reply_text(f"💳 Upgrade to Premium: {session.url}")
    except Exception as e:
        logger.exception("Failed to create Stripe session")
        update.message.reply_text(f"⚠️ Payment link error: {e}")

# message handler
def handle_message(update, context):
    try:
        uid = update.message.from_user.id
        text = (update.message.text or "").strip()
        if not text:
            update.message.reply_text("Please send text for analysis.")
            return

        # check usage
        ok, cnt = check_and_increment_usage(uid)
        if not ok:
            update.message.reply_text(f"Daily limit reached ({DAILY_LIMIT}). Use /upgrade.")
            return

        rule = analyze_text_rule_based(text)
        score = rule["score"]

        # ambiguous -> try OpenAI fallback
        if AMBIGUOUS_LOW < score < AMBIGUOUS_HIGH:
            ai = analyze_with_openai(text)
            if ai.get("ok"):
                update.message.reply_text(ai["raw"])
                return
            else:
                logger.warning("OpenAI fallback failed: %s", ai.get("message"))

        # otherwise reply with rule-based formatted result
        update.message.reply_text(format_result(rule), parse_mode=ParseMode.MARKDOWN)
    except Exception:
        logger.exception("handle_message failed")
        update.message.reply_text("⚠️ An error occurred. Try again later.")

def format_result(parsed):
    verdict = parsed.get("verdict", "Unknown")
    score = parsed.get("score", None)
    reasons = parsed.get("reasons", [])
    advice = parsed.get("advice", "")
    explain = parsed.get("explain", "")
    share = parsed.get("share_text", "")

    emoji = {"High": "⚠️", "Medium": "❗", "Low": "✅"}.get(verdict, "ℹ️")
    header = f"{emoji} *Verdict:* *{verdict}*"
    if isinstance(score, int):
        header += f"  _(score: {score}/100)_"

    body = ""
    if reasons:
        body += "\n*Top flags:*"
        for r in reasons[:5]:
            body += f"\n• {r}"
    body += f"\n\n*Advice:* {advice}"
    if explain:
        body += f"\n\n_{explain}_"
    if share:
        body += f"\n\n_You can forward:_\n`{share}`"
    return header + body

# register handlers
dispatcher.add_handler(CommandHandler("start", cmd_start))
dispatcher.add_handler(CommandHandler("help", cmd_help))
dispatcher.add_handler(CommandHandler("status", cmd_status))
dispatcher.add_handler(CommandHandler("upgrade", cmd_upgrade))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))

# ---------------- Stripe endpoints ----------------
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

    # Process checkout completed
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
                bot.send_message(chat_id=int(tg), text="⚠️ Payment failed. Please update your payment method.")
            except Exception:
                logger.exception("Failed to notify user of failed payment")

    return jsonify({"ok": True})

# ---------------- Telegram webhook route ----------------
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

# optional reset
@app.route("/reset-webhook", methods=["GET"])
def reset_webhook():
    try:
        bot.delete_webhook()
        ok = bot.set_webhook(url=build_webhook_url())
        return jsonify({"ok": ok})
    except Exception:
        logger.exception("reset failed")
        return jsonify({"ok": False}), 500

# ---------------- start ----------------
if __name__ == "__main__":
    register_webhook()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
