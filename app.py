# app.py
# Webhook-only ScamShield: rule-based detector + OpenAI fallback (ambiguous cases)
# Works with python-telegram-bot v13.x (Dispatcher style) + Flask webhook

import os
import re
import json
import logging
import traceback
from datetime import date
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from telegram import Bot, Update, ParseMode
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters

import openai

# ------------------ Logging ------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scamshield")

# ------------------ Config / Env ------------------
TOKEN = os.getenv("TELEGRAM_TOKEN") or os.getenv("TG_BOT_TOKEN")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")  # optional, used for ambiguous fallback
BASE_URL = os.getenv("BASE_URL")  # optional; fallback to Render hostname if missing
DAILY_LIMIT = int(os.getenv("DAILY_LIMIT", "10"))

if not TOKEN:
    logger.error("Missing TELEGRAM_TOKEN (set in Render env).")
    raise SystemExit("Missing TELEGRAM_TOKEN")

# initialize OpenAI if key present
if OPENAI_KEY:
    openai.api_key = OPENAI_KEY
else:
    logger.info("OPENAI_API_KEY not set. LLM fallback will be disabled.")

# ------------------ Files for storage ------------------
USAGE_FILE = "usage.json"         # per-user daily counts
PREMIUM_FILE = "premium_users.json"  # reserved for future paid plan (keep file)

def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f)
    except Exception as e:
        logger.exception("Failed to save %s: %s", path, e)

# ------------------ Usage / limits ------------------
def check_and_increment_usage(user_id):
    data = load_json(USAGE_FILE)
    today = date.today().isoformat()
    s = str(user_id)
    entry = data.get(s, {"date": today, "count": 0})
    if entry.get("date") != today:
        entry = {"date": today, "count": 0}
    if entry["count"] >= DAILY_LIMIT:
        data[s] = entry
        save_json(USAGE_FILE, data)
        return False, entry["count"]
    entry["count"] += 1
    data[s] = entry
    save_json(USAGE_FILE, data)
    return True, entry["count"]

def is_premium(user_id):
    data = load_json(PREMIUM_FILE)
    return str(user_id) in data

# ------------------ Rule-based analyzer ------------------
SUSPICIOUS_KEYWORDS = [
    r"wire transfer", r"western union", r"bank transfer", r"send money",
    r"urgent", r"act now", r"verify your account", r"click the link",
    r"limited time", r"winner", r"congratulations", r"prize", r"lottery",
    r"claim now", r"password", r"account suspended", r"deposit", r"loan",
    r"lottery", r"verify identity", r"final notice", r"one-time offer"
]
URL_SHORTENERS = r"(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|tiny\.cc|is\.gd|buff\.ly)"
PHONE_SHORT_CODE = r"\b\d{4,6}\b"

def score_keywords(text):
    score = 0
    reasons = []
    low = text.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if re.search(kw, low):
            score += 18
            reasons.append(f"Suspicious phrase: '{kw}'")
    if re.search(r"http[s]?://", text):
        score += 12
        reasons.append("Contains URL")
    if re.search(URL_SHORTENERS, text, re.I):
        score += 25
        reasons.append("Contains shortened URL")
    if re.search(r"\$(\s)?\d{2,}", text) or re.search(r"\d+\s?USD", text, re.I):
        score += 12
        reasons.append("Mentions money or payments")
    if re.search(r"!!!|!!", text):
        score += 8
        reasons.append("Urgent punctuation")
    if sum(1 for c in text if c.isupper()) > max(6, len(text)*0.12):
        score += 6
        reasons.append("Unusual capitalization (shouting)")
    if re.search(PHONE_SHORT_CODE, text):
        score += 6
        reasons.append("Short numeric code present")
    return score, reasons

def find_urls(text):
    urls = re.findall(r"https?://[^\s]+", text)
    return urls

def analyze_text_rule_based(text):
    score = 0
    reasons = []
    s, r = score_keywords(text)
    score += s; reasons += r

    urls = find_urls(text)
    if urls:
        # domain heuristics (placeholder)
        score += 8
        reasons.append(f"URL(s) detected: {', '.join(urls)[:200]}")

    # clamp
    score = min(100, int(score))

    if score >= 60:
        verdict = "High"
        advice = "Do NOT click links or reply. Verify through official channels."
    elif score >= 30:
        verdict = "Medium"
        advice = "Be cautious — check sender details and links before interacting."
    else:
        verdict = "Low"
        advice = "Appears low risk, but always verify requests for money or credentials."

    explain = f"Rule-based analysis gave a score of {score}/100."
    share_text = f"{verdict} risk ({score}/100) — {advice}"
    return {
        "verdict": verdict,
        "score": score,
        "reasons": reasons[:8],
        "advice": advice,
        "explain": explain,
        "share_text": share_text
    }

# ------------------ OpenAI fallback (ambiguous cases) ------------------
AMBIGUOUS_LOW = 15
AMBIGUOUS_HIGH = 60

def analyze_with_openai(text):
    if not OPENAI_KEY:
        return {"error": "no_openai", "message": "OpenAI API key not configured."}
    try:
        resp = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are ScamShield, an expert at detecting scams. Return a short structured answer explaining if a message is scammy and why."},
                {"role": "user", "content": f"Analyze this message for scams and return a short verdict, reasons and advice:\n\n{text}"}
            ],
            temperature=0.0,
            max_tokens=250,
        )
        content = resp["choices"][0]["message"]["content"].strip()
        return {"ok": True, "raw": content}
    except Exception as e:
        logger.error("OpenAI call failed: %s", e)
        logger.error(traceback.format_exc())
        return {"error": "openai_error", "message": str(e)}

# ------------------ Formatting for Telegram (Markdown) ------------------
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

# ------------------ Bot + Flask setup (webhook) ------------------
bot = Bot(token=TOKEN)
dispatcher = Dispatcher(bot, None, workers=4, use_context=True)
app = Flask(__name__)

# ------------------ Helpers to compute webhook URL ------------------
def build_webhook_url():
    if BASE_URL:
        base = BASE_URL.rstrip("/")
    else:
        host = os.environ.get("RENDER_EXTERNAL_HOSTNAME") or os.environ.get("RENDER_EXTERNAL_URL")
        if not host:
            raise RuntimeError("Set BASE_URL or ensure RENDER_EXTERNAL_HOSTNAME/RENDER_EXTERNAL_URL present")
        if host.startswith("http"):
            base = host.rstrip("/")
        else:
            base = f"https://{host.rstrip('/')}"
    return f"{base}/webhook/{TOKEN}"

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

# ------------------ Telegram handlers ------------------
def cmd_start(update, context):
    update.message.reply_text("👋 ScamShield AI — paste a suspicious message and I'll check it. (Free: %d/day)" % DAILY_LIMIT)

def cmd_help(update, context):
    update.message.reply_text("Send any text and I'll analyze it. Use /start to see usage and /help for this text.")

def cmd_upgrade(update, context):
    update.message.reply_text("Upgrade/paid plan coming soon. For now free daily limit applies.")

def handle_update(update, context):
    user = update.message.from_user
    text = (update.message.text or "").strip()
    if not text:
        update.message.reply_text("Please send the suspicious message (some text).")
        return

    # Premium bypass
    if not is_premium(user.id):
        ok, count = check_and_increment_usage(user.id)
        if not ok:
            update.message.reply_text(f"Daily free checks reached ({DAILY_LIMIT}). Upgrade will lift limits.")
            return

    # 1) Run rule-based analyzer
    rule_res = analyze_text_rule_based(text)
    score = rule_res["score"]

    # 2) If ambiguous, call OpenAI fallback (minimize calls)
    if AMBIGUOUS_LOW < score < AMBIGUOUS_HIGH:
        ai = analyze_with_openai(text)
        if ai.get("ok"):
            # If OpenAI returned structured raw text, show raw reply below (best-effort parsing)
            reply_text = ai.get("raw")
            update.message.reply_text(reply_text)
            return
        else:
            # OpenAI failure -> proceed with rule result but log
            logger.warning("OpenAI fallback failed: %s", ai.get("message"))

    # 3) Format and reply using rule-based
    reply_md = format_result(rule_res)
    update.message.reply_text(reply_md, parse_mode=ParseMode.MARKDOWN)

# ------------------ Flask routes ------------------
@app.route("/")
def index():
    return "ScamShield (rule-based + AI fallback) running ✅"

@app.route(f"/webhook/{TOKEN}", methods=["POST"])
def webhook():
    try:
        data = request.get_json(force=True)
        update = Update.de_json(data, bot)
        dispatcher.process_update(update)
        return jsonify({"ok": True})
    except Exception:
        logger.exception("Webhook processing failed")
        return jsonify({"ok": False}), 500

# optional helper to reset webhook manually
@app.route("/reset-webhook", methods=["GET"])
def reset_webhook():
    try:
        bot.delete_webhook()
        ok = bot.set_webhook(url=build_webhook_url())
        return jsonify({"ok": ok})
    except Exception:
        logger.exception("reset-webhook failed")
        return jsonify({"ok": False}), 500

# ------------------ Register handlers on dispatcher ------------------
dispatcher.add_handler(CommandHandler("start", cmd_start))
dispatcher.add_handler(CommandHandler("help", cmd_help))
dispatcher.add_handler(CommandHandler("upgrade", cmd_upgrade))
dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_update))

# ------------------ Startup ------------------
if __name__ == "__main__":
    register_webhook()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
