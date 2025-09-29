# app.py
# ScamShield bot with premium, promo codes, and Stripe test mode

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

# ---------------- config/env ----------------
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
if not TELEGRAM_TOKEN:
    raise SystemExit("❌ Missing TELEGRAM_TOKEN")

BASE_URL = os.getenv("BASE_URL")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
DAILY_LIMIT = int(os.getenv("DAILY_LIMIT", "10"))

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
ADMIN_IDS = os.getenv("ADMIN_IDS", "").split(",")

if OPENAI_KEY:
    openai.api_key = OPENAI_KEY

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

# ---------------- promo codes ----------------
PROMO_FILE = "promo_codes.json"

def load_promo_codes():
    try:
        with open(PROMO_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def redeem_promo(user_id, code):
    codes = load_promo_codes()
    if code not in codes:
        return False, "❌ Invalid promo code."
    days = codes[code]
    set_premium(user_id, days=days)
    return True, f"🎉 Promo applied! You are premium for {days} days."

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

# ---------------- scam analyzer ----------------
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
        reasons.append(f"Contains URL(s): {', '.join(urls)[:200]}")
        if re.search(URL_SHORTENERS, " ".join(urls), re.I):
            score += 25
            reasons.append("Shortened URL detected")

    if re.search(r"\$\s?\d{2,}", text) or re.search(r"\d+\s?USD", text, re.I):
        score += 12
        reasons.append("Mentions money or payment")

    if re.search(r"!!+|!!!", text):
        score += 8
        reasons.append("Urgency punctuation")

    if sum(1 for c in text if c.isupper()) > max(6, int(len(text)*0.12)):
        score += 6
        reasons.append("Many uppercase characters")

    score = min(100, int(score))
    if score >= 60:
        verdict = "High"
        advice = "Do NOT click links or reply. Verify independently."
    elif score >= 30:
        verdict = "Medium"
        advice = "Be cautious — check sender identity and links."
    else:
        verdict = "Low"
        advice = "Appears low risk, but always verify."

    return {
        "verdict": verdict,
        "score": score,
        "reasons": reasons[:8],
        "advice": advice,
        "explain": f"Rule-based score {score}/100"
    }

# ---------------- OpenAI fallback ----------------
AMBIG_LOW, AMBIG_HIGH = 15, 60

def analyze_with_openai(text):
    if not OPENAI_KEY:
        return {"error": "no_openai"}
    try:
        resp = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are ScamShield, short and precise."},
                {"role": "user", "content": f"Analyze this message:\n\n{text}"}
            ],
            temperature=0.0,
            max_tokens=300,
        )
        return {"ok": True, "raw": resp["choices"][0]["message"]["content"].strip()}
    except Exception as e:
        return {"error": "openai_error", "message": str(e)}

# ---------------- Telegram bot ----------------
bot = Bot(token=TELEGRAM_TOKEN)
dispatcher = Dispatcher(bot, None, workers=4, use_context=True)
app = Flask(__name__)

def cmd_start(update, context):
    uid = update.message.from_user.id
    text = (f"👋 ScamShield AI — paste a suspicious message and I'll check it.\n"
            f"Free users: {DAILY_LIMIT}/day. Upgrade for unlimited.\n\n"
            f"🔑 Use /redeem CODE if you have a promo code.\n"
            f"💳 Or subscribe here:\n{BASE_URL}/subscribe?telegram_id={uid}")
    update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

def cmd_help(update, context):
    update.message.reply_text("Send a message to analyze. Use /redeem CODE or /subscribe to upgrade.")

def cmd_subscribe(update, context):
    uid = update.message.from_user.id
    link = f"{BASE_URL}/subscribe?telegram_id={uid}"
    update.message.reply_text(f"Subscribe here: {link}")

def cmd_redeem(update, context):
    uid = update.message.from_user.id
    if not context.args:
        update.message.reply_text("Usage: /redeem CODE")
        return
    code = context.args[0].strip()
    ok, msg = redeem_promo(uid, code)
    update.message.reply_text(msg)

def handle_update(update, context):
    try:
        uid = update.message.from_user.id
        text = (update.message.text or "").strip()
        if not text:
            update.message.reply_text("Please send text.")
            return
        ok, count = check_and_increment_usage(uid)
        if not ok:
            update.message.reply_text(f"Daily limit reached ({DAILY_LIMIT}). Use /redeem or /subscribe.")
            return
        rule = analyze_text_rule_based(text)
        score = rule["score"]
        if AMBIG_LOW < score < AMBIG_HIGH:
            ai = analyze_with_openai(text)
            if ai.get("ok"):
                update.message.reply_text(ai["raw"])
                return
        update.message.reply_text(format_result(rule), parse_mode=ParseMode.MARKDOWN)
    except Exception:
        update.message.reply_text("⚠️ Error occurred.")

def format_result(parsed):
    verdict = parsed.get("verdict", "Unknown")
    score = parsed.get("score", 0)
    reasons = parsed.get("reasons", [])
    advice = parsed.get("advice", "")
    explain = parsed.get("explain", "")
    emoji = {"High": "⚠️", "Medium": "❗", "Low": "✅"}.get(verdict, "ℹ️")
    body = f"{emoji} *Verdict:* {verdict} _(score: {score}/100)_\n"
    if reasons:
        body += "\n*Reasons:*"
        for r in reasons:
            body += f"\n• {r}"
    body += f"\n\n*Advice:* {advice}\n_{explain}_"
    return body

# handlers
dispatcher.add_handler(CommandHandler("start", cmd_start))
dispatcher.add_handler(CommandHandler("help", cmd_help))
dispatcher.add_handler(CommandHandler("subscribe", cmd_subscribe))
dispatcher.add_handler(CommandHandler("redeem", cmd_redeem))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_update))

# ---------------- webhook helpers ----------------
def build_webhook_url():
    return f"{BASE_URL.rstrip('/')}/webhook/{TELEGRAM_TOKEN}"

def register_webhook():
    url = build_webhook_url()
    bot.delete_webhook()
    bot.set_webhook(url=url)

# ---------------- Flask routes ----------------
@app.route(f"/webhook/{TELEGRAM_TOKEN}", methods=["POST"])
def telegram_webhook():
    data = request.get_json(force=True)
    update = Update.de_json(data, bot)
    dispatcher.process_update(update)
    return jsonify({"ok": True})

if __name__ == "__main__":
    register_webhook()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
