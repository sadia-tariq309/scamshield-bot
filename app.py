# app.py
# ScamShield Bot: Telegram webhook bot + rule-based scam detector + premium (Stripe test mode) + SQLite

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
import telegram
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters

# ---------------- logging ----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scamshield")

# ---------------- config/env ----------------
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN") or os.getenv("TG_BOT_TOKEN")
if not TELEGRAM_TOKEN:
    raise SystemExit("❌ TELEGRAM_TOKEN is missing in Render environment!")

BASE_URL = os.getenv("BASE_URL")  # your Render URL
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
DAILY_LIMIT = int(os.getenv("DAILY_LIMIT", "10"))

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

if OPENAI_KEY:
    openai.api_key = OPENAI_KEY
else:
    logger.info("OPENAI_API_KEY not set — LLM fallback disabled.")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# ---------------- storage (SQLite) ----------------
DB_FILE = "scamshield_users.db"

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
    logger.info("✅ Premium set for %s until %s", telegram_id, until)

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

# ---------------- usage limits ----------------
USAGE_FILE = "usage_counts.json"

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

# ---------------- rule-based scam detector ----------------
SUSPICIOUS_KEYWORDS = [
    r"wire transfer", r"western union", r"bank transfer", r"send money",
    r"urgent", r"verify your account", r"click the link", r"limited time",
    r"winner", r"congratulations", r"prize", r"lottery", r"claim now",
    r"password", r"account suspended", r"deposit", r"loan", r"final notice"
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
        reasons.append(f"Contains URL(s): {', '.join(urls)[:200]}")
        if re.search(URL_SHORTENERS, " ".join(urls), re.I):
            score += 25
            reasons.append("Shortened URL detected")

    if re.search(r"\$\s?\d{2,}", text) or re.search(r"\d+\s?USD", text, re.I):
        score += 12
        reasons.append("Mentions money")

    if re.search(r"!!+|!!!", text):
        score += 8
        reasons.append("Urgency punctuation")

    if sum(1 for c in text if c.isupper()) > max(6, int(len(text)*0.12)):
        score += 6
        reasons.append("Many uppercase characters")

    score = min(100, int(score))
    verdict = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    advice = (
        "Do NOT click links or reply." if verdict == "High" else
        "Be cautious, verify sender." if verdict == "Medium" else
        "Appears low risk, but stay alert."
    )
    return {
        "verdict": verdict, "score": score, "reasons": reasons[:8],
        "advice": advice, "explain": f"Rule-based score {score}/100"
    }

# ---------------- OpenAI fallback ----------------
AMBIGUOUS_LOW, AMBIGUOUS_HIGH = 15, 60

def analyze_with_openai(text):
    if not OPENAI_KEY:
        return {"error": "no_openai"}
    try:
        resp = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are ScamShield. Short and precise."},
                {"role": "user", "content": f"Analyze:\n\n{text}"}
            ],
            temperature=0.0, max_tokens=300,
        )
        return {"ok": True, "raw": resp["choices"][0]["message"]["content"].strip()}
    except Exception as e:
        logger.error("OpenAI error: %s", e)
        return {"error": "openai_error"}

# ---------------- Telegram bot + Flask ----------------
bot = telegram.Bot(token=TELEGRAM_TOKEN)
dispatcher = Dispatcher(bot, None, workers=4, use_context=True)
app = Flask(__name__)

# commands
def cmd_start(update, context):
    uid = update.message.from_user.id
    link = f"{BASE_URL.rstrip('/')}/subscribe?telegram_id={uid}"
    update.message.reply_text(
        f"👋 ScamShield AI\nSend any suspicious message.\n\n"
        f"Free: {DAILY_LIMIT}/day. Upgrade for unlimited.\n"
        f"👉 [Subscribe here]({link})", parse_mode="Markdown")

def cmd_help(update, context):
    update.message.reply_text("Send text to analyze. Use /subscribe to get premium.")

def cmd_subscribe(update, context):
    uid = update.message.from_user.id
    link = f"{BASE_URL.rstrip('/')}/subscribe?telegram_id={uid}"
    update.message.reply_text(f"👉 Subscribe here: {link}")

def handle_update(update, context):
    uid = update.message.from_user.id
    text = (update.message.text or "").strip()
    if not text:
        return update.message.reply_text("Please send text.")

    ok, _ = check_and_increment_usage(uid)
    if not ok:
        return update.message.reply_text("Daily limit reached. Use /subscribe to upgrade.")

    rule = analyze_text_rule_based(text)
    score = rule["score"]

    if AMBIGUOUS_LOW < score < AMBIGUOUS_HIGH:
        ai = analyze_with_openai(text)
        if ai.get("ok"):
            return update.message.reply_text(ai["raw"])

    update.message.reply_text(format_result(rule), parse_mode="Markdown")

def format_result(parsed):
    emoji = {"High": "⚠️", "Medium": "❗", "Low": "✅"}.get(parsed["verdict"], "ℹ️")
    msg = f"{emoji} *Verdict:* {parsed['verdict']} (score {parsed['score']}/100)\n"
    if parsed["reasons"]:
        msg += "\n*Flags:* " + ", ".join(parsed["reasons"][:5])
    msg += f"\n\n*Advice:* {parsed['advice']}\n_{parsed['explain']}_"
    return msg

# register handlers
dispatcher.add_handler(CommandHandler("start", cmd_start))
dispatcher.add_handler(CommandHandler("help", cmd_help))
dispatcher.add_handler(CommandHandler("subscribe", cmd_subscribe))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_update))

# ---------------- webhook helpers ----------------
def build_webhook_url():
    base = BASE_URL.rstrip("/") if BASE_URL else f"https://{os.environ.get('RENDER_EXTERNAL_HOSTNAME')}"
    return f"{base}/webhook/{TELEGRAM_TOKEN}"

def register_webhook():
    url = build_webhook_url()
    bot.delete_webhook()
    ok = bot.set_webhook(url=url)
    logger.info("Webhook set: %s", ok)

# ---------------- Stripe ----------------
@app.route("/subscribe")
def subscribe():
    tg = request.args.get("telegram_id")
    if not STRIPE_PRICE_ID or not STRIPE_SECRET_KEY:
        return "Stripe not configured", 500
    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        mode="subscription",
        success_url=f"{BASE_URL.rstrip('/')}/success",
        cancel_url=f"{BASE_URL.rstrip('/')}/cancel",
        client_reference_id=str(tg) if tg else None,
    )
    return redirect(session.url, code=302)

@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    if event["type"] == "checkout.session.completed":
        tg = event["data"]["object"].get("client_reference_id")
        if tg:
            set_premium(tg, 30)
            bot.send_message(chat_id=int(tg), text="🎉 Subscription active! You are Premium.")
    return jsonify({"ok": True})

# ---------------- Flask routes ----------------
@app.route(f"/webhook/{TELEGRAM_TOKEN}", methods=["POST"])
def telegram_webhook():
    data = request.get_json(force=True)
    update = telegram.Update.de_json(data, bot)
    dispatcher.process_update(update)
    return jsonify({"ok": True})

@app.route("/reset-webhook")
def reset_webhook():
    ok = bot.set_webhook(url=build_webhook_url())
    return jsonify({"ok": ok})

# ---------------- start ----------------
if __name__ == "__main__":
    register_webhook()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
