from telegram.ext import Updater, CommandHandler, MessageHandler, Filters
import openai
import os
import logging

# Enable logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scamshield")

TG_TOKEN = os.getenv("TG_BOT_TOKEN") or os.getenv("TELEGRAM_TOKEN")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

openai.api_key = OPENAI_API_KEY

def start(update, context):
    update.message.reply_text("👋 ScamShield AI is live and protecting you!")

def help_cmd(update, context):
    update.message.reply_text("ℹ️ Available commands: /start, /upgrade, or just chat with me!")

def upgrade_cmd(update, context):
    update.message.reply_text("⚡ Upgrade feature coming soon!")

def handle_message(update, context):
    user_text = update.message.text
    try:
        # Send to OpenAI
        response = openai.Completion.create(
            engine="text-davinci-003",  # You can use gpt-3.5-turbo if you prefer
            prompt=user_text,
            max_tokens=200
        )
        reply = response.choices[0].text.strip()
        update.message.reply_text(reply)
    except Exception as e:
        logger.error(f"OpenAI error: {e}")
        update.message.reply_text("❌ Sorry, I had trouble processing your message.")

def main():
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
