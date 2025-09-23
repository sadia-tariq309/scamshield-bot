# app.py
# Render-ready ScamShield bot (Telegram + OpenAI + Stripe + Flask webhook)
# Requirements: python-telegram-bot==13.15, openai, flask, stripe, requests

import os
import json
import logging
import re
import threading
from datetime import date, datetime
from flask import Flask, request, jsonify
import openai
import stripe
from telegram import ParseMode
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scamshield")

# ---------------------------
# Environment / config
# ---------------------------
TG_TOKEN = os.environ.get("TG_BOT_TOKEN") or os.environ.get("TELEGRAM_TOKEN")
OPENAI_KEY = os.environ.get("OPENAI_API_KEY")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")  # set after webhook creation
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID")
BASE_URL = os.environ.get("BASE_URL", "")  # e.g. https://your-app.onrender.com

OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo")
MAX_TOKENS = int(os.environ.get("MAX_TOKENS", "300"))
TEMPERATURE = float(os.environ.get("TEMPERATURE", "0.0"))

USAGE_FILE = "usage.json"
PREMIUM_FILE = "premium_users.json"
DAILY_LIMIT = int(os.environ.get("DAILY_LIMIT", "10"))

# Quick env validation (print helpful logs)
missing = []
if not TG_TOKEN:
    missing.append("TG_BOT_TOKEN / TELEGRAM_TOKEN")
if not OPENAI_KEY:
    missing.append("OPENAI_API_KEY")
if not STRIPE_SECRET_KEY:
    logger.warning("STRIPE_SECRET_KEY not set (you can still test AI checks).")
if not STRIPE_PRICE_ID:
    logger.warning("STRIPE_PRICE_ID not set (Stripe /upgrade will fail until set).")
if missing:
    logger.error("Missing env vars: %s", ", ".join(missing))
    # We won't exit because you might want to test locally without all secrets.

# ---------------------------
# Setup API clients
# ---------------------------
if OPENAI_KEY:
    openai.api_key = OPENAI_KEY
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# ---------------------------
# Prompt (strict JSON)
# ---------------------------
ANALYSIS_PROMPT = """
You are "ScamShield", an expert at spotting scams and phishing in short messages (sms, whatsapp, email).
Given an input message, RETURN EXACTLY one JSON object and nothing else with this shape:

{
  "verdict": "High" | "Medium" | "Low",
  "score": integer 0-100,
  "reasons": ["short reason 1", "short reason 2", ...],
  "advice": "one-sentence instruction (e.g. 'Do not click links.')",
  "explain": "1-2 sentence plain-language explanation",
  "share_text": "one-line message a user can forward to family"
}
"""

# ---------------------------
# File helpers
# ---------------------------
def load_json_file(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_json_file(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f)
    except Exception as e:
        logger.exception("Failed saving %s: %s", path, e)

# ---------------------------
# Usage tracking (daily limits)
# ---------------------------
def check_and_increment_usage(user_id):
    data = load_json_file(USAGE_FILE)
    today = date.today().isoformat()
    entry = data.get(str(user_id), {"date": today, "count": 0})
    if entry.get("date") != today:
        entry = {"date": today, "count": 0}
    if entry["count"] >= DAILY_LIMIT:
        data[str(user_id)] = entry
        save_json_file(USAGE_FILE, data)
        return False, entry["count"]
    entry["count"] += 1
    data[str(user_id)] = entry
    save_json_file(USAGE_FILE, data)
    return True, entry["count"]

# ---------------------------
# Premium users
# ---------------------------
def load_premium():
    return load_json_file(PREMIUM_FILE)

def save_premium(data):
    save_json_file(PREMIUM_FILE, data)

def grant_premium(user_id, plan="monthly"):
    data = load_premium()
    data[str(user_id)] = {"since": datetime.utcnow().isoformat(), "plan": plan}
    save_premium(data)

def is_premium(user_id):
    return str(user_id) in load_premium()

# ---------------------------
# Robust JSON extraction
# ---------------------------
def extract_json_from_text(text):
    # Try first { ... } substring
    try:
        start = text.index("{")
        end = text.rindex("}") + 1
        candidate = text[start:end]
        return json.loads(candidate)
    except Exception:
        pass
    # Fallback: regex find {...}
    candidates = re.findall(r"\{[\s\S]*?\}", text)
    for c in candidates:
        try:
            return json.loads(c)
        except Exception:
            continue
    return None

# ---------------------------
# OpenAI call
# ---------------------------
def analyze_text_with_openai(message_text):
    if not OPENAI_KEY:
        return {"error": "openai_missing", "message": "No OpenAI key configured."}
    system_msg = {"role": "system", "content": ANALYSIS_PROMPT}
    user_msg = {"role": "user", "content": message_text}
    try:
        resp = openai.ChatCompletion.create(
            model=OPENAI_MODEL,
            messages=[system_msg, user_msg],
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
        )
    except Exception as e:
        logger.exception("OpenAI request failed")
        return {"error": "openai_error", "message": str(e)}
    try:
        content = resp["choices"][0]["message"]["content"].strip()
    except Exception:
        return {"error": "no_content", "raw": resp}
    parsed = extract_json_from_text(content)
    if parsed:
        return {"parsed": parsed, "raw": content}
    else:
        return {"error": "parse_failed", "raw": content}

# ---------------------------
# Formatting for Telegram
# ---------------------------
def format_result(parsed):
    verdict = parsed.get("verdict", "Unknown")
    score = parsed.get("score", None)
    reasons = parsed.get("reasons", [])
    advice = parsed.get("advice", "")
    explain = parsed.get("explain", "")
    share_text = parsed.get("share_text", "")

    emoji = {"High": "⚠️", "Medium": "❗", "Low": "✅"}.get(verdict, "ℹ️")
    header = f"{emoji} *Verdict:* *{verdict}*"
    if isinstance(score, int):
        header += f"  _(score: {score}/100)_"

    reasons_text = ""
    if reasons:
        reasons_text = "\n*Top red flags:*"
        for r in reasons[:5]:
            r_escaped = r.replace("_", "\\_").replace("*", "\\*").replace("`", "\\`")
            reasons_text += f"\n• {r_escaped}"

    advice_text = f"\n*Advice:* {advice}"
    explain_text = f"\n\n{explain}"
    share_block = f"\n\n_You can forward this to family:_\n`{share_text}`" if share_text else ""

    return header + reasons_text + advice_text + explain_text + share_block

# ---------------------------
# Stripe checkout creation
# ---------------------------
def create_checkout_session_for_user(telegram_user_id):
    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID or not BASE_URL:
        logger.warning("Stripe config incomplete for checkout creation")
        return None
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            metadata={"telegram_id": str(telegram_user_id)},
            success_url=BASE_URL + "/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=BASE_URL + "/cancel",
        )
        return session.url
    except Exception as e:
        logger.exception("Stripe checkout create failed")
        return None

# ---------------------------
# Flask app for webhook + pages
# ---------------------------
app = Flask(__name__)

@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", None)
    if not STRIPE_WEBHOOK_SECRET:
        logger.error("STRIPE_WEBHOOK_SECRET not configured")
        return jsonify({"error": "webhook secret not configured"}), 500
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        logger.exception("Invalid payload")
        return jsonify({"error": "invalid payload"}), 400
    except stripe.error.SignatureVerificationError:
        logger.exception("Invalid signature")
        return jsonify({"error": "invalid signature"}), 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        telegram_id = session.get("metadata", {}).get("telegram_id")
        if telegram_id:
            grant_premium(telegram_id)
            logger.info("Granted premium to user %s", telegram_id)
        else:
            logger.warning("checkout.session.completed has no telegram_id metadata")
    return jsonify({"status": "ok"}), 200

@app.route("/success")
def success_page():
    return "<h2>Payment received — ScamShield Premium is active. Return to Telegram.</h2>"

@app.route("/cancel")
def cancel_page():
    return "<h2>Payment canceled. No charge made.</h2>"

def start_flask_thread():
    port = int(os.environ.get("PORT", "10000"))
    def run():
        logger.info("Starting Flask on port %s", port)
        app.run(host="0.0.0.0", port=port)
    t = threading.Thread(target=run)
    t.daemon = True
    t.start()

# ---------------------------
# Telegram handlers
# ---------------------------
def start(update, context):
    update.message.reply_text(
        "Welcome to ScamShield AI ⚠️\nPaste a suspicious message (SMS, WhatsApp or email) and I'll check it.\nNote: suggestions only — verify with official sources for money requests."
    )

def help_cmd(update, context):
    update.message.reply_text(
        "Commands:\n/start - Start\n/help - This help\n/upgrade - Upgrade to Premium\n\nFree: 10 checks/day. Premium: unlimited."
    )

def upgrade_cmd(update, context):
    user = update.message.from_user
    checkout_url = create_checkout_session_for_user(user.id)
    if checkout_url:
        update.message.reply_text(
            f"To upgrade to ScamShield Premium, pay here:\n{checkout_url}\nAfter payment your account will be upgraded automatically."
        )
    else:
        update.message.reply_text("⚠️ Sorry, there was an issue creating your upgrade link. Please try again later.")

def handle_message(update, context):
    user = update.message.from_user
    text = update.message.text or ""
    text = text.strip()
    if len(text) < 6:
        update.message.reply_text("Please paste the suspicious message (a few words).")
        return

    # Premium bypass
    if not is_premium(user.id):
        ok, _ = check_and_increment_usage(user.id)
        if not ok:
            update.message.reply_text(f"Daily limit reached ({DAILY_LIMIT}). Upgrade for unlimited: /upgrade")
            return

    update.message.reply_text("Analyzing... 🔎 (this may take a few seconds)")

    result = analyze_text_with_openai(text)
    if result.get("error") == "openai_missing":
        update.message.reply_text("AI not configured. Contact the admin.")
        return
    if result.get("error") == "openai_error":
        update.message.reply_text("Sorry, analysis is temporarily unavailable. Try again later.")
        logger.error("OpenAI error: %s", result.get("message"))
        return

    if "parsed" in result:
        reply_md = format_result(result["parsed"])
        update.message.reply_text(reply_md, parse_mode=ParseMode.MARKDOWN)
    else:
        raw = result.get("raw", "")
        short = "I couldn't parse the model output reliably. Raw:\n\n" + (raw[:1500] if raw else "No output")
        update.message.reply_text(short)

# ---------------------------
# Main: start bot + flask thread
# ---------------------------
def main():
    # report missing important env vars
    if not TG_TOKEN:
        logger.error("TG_BOT_TOKEN not set. Set TG_BOT_TOKEN or TELEGRAM_TOKEN env var and redeploy.")
        return
    # start Flask (webhook receiver)
    start_flask_thread()

    # start Telegram polling
    updater = Updater(TG_TOKEN, use_context=True)
    dp = updater.dispatcher
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("help", help_cmd))
    dp.add_handler(CommandHandler("upgrade", upgrade_cmd))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))

    updater.start_polling()
    logger.info("Bot started (polling).")
    updater.idle()

if __name__ == "__main__":
    main()
