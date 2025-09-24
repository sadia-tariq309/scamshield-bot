import os
import logging
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters

# --- Logging setup ---
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("scamshield")

# --- Load environment variables ---
TG_TOKEN = os.getenv("TELEGRAM_TOKEN")  # must match Render environment name
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not TG_TOKEN or not OPENAI_API_KEY:
    logger.error("Missing TELEGRAM_TOKEN or OPENAI_API_KEY. Please set them in Render.")
    exit(1)


# --- Handlers ---
def start(update, context):
    update.message.reply_text("✅ Hello! ScamShield Bot is online. Use /help for commands.")


def help_cmd(update, context):
    update.message.reply_text("ℹ️ Available commands:\n/start - Start bot\n/help - Show this message\n/upgrade - Coming soon!")


def upgrade_cmd(update, context):
    update.message.reply_text("⚡ Upgrade feature is under development.")


def handle_message(update, context):
    text = update.message.text
    update.message.reply_text(f"🤖 You said: {text}")


# --- Main bot setup ---
def main():
    updater = Updater(TG_TOKEN, use_context=True)
    dp = updater.dispatcher

    # Command handlers
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("help", help_cmd))
    dp.add_handler(CommandHandler("upgrade", upgrade_cmd))

    # Fallback text handler
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))

    # Start polling
    updater.start_polling()
    logger.info("✅ Bot started (polling).")
    updater.idle()


if __name__ == "__main__":
    main()
