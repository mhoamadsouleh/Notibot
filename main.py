###############libs###############

import telebot, os, subprocess, shutil, time, requests
from datetime import datetime
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

###############tokenbot###############

token = os.environ.get("7723535106:AAFJfJn9TWIBQBxjgL7NbT_JVvSD1nQodF4")
ADMIN_ID = os.environ.get("6186106102")  # يجب أن يكون نصًا
SOLO = telebot.TeleBot(token)

###############definitions###############

UPLOAD_FOLDER = "./vps_upload_bot"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
uploaded_files = {}
user_uploads = {}
unlimited_users = set()
API_KEY = os.environ.get("2ec241972ed224405090681092436f106705ac33be3cd3b94d09d2725581891b")
url_scan = "https://www.virustotal.com/api/v3/files"
url_report = "https://www.virustotal.com/api/v3/analyses/"
headers = {"x-apikey": API_KEY}

###############filescan###############

def scan(file_path):
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            response = requests.post(url_scan, headers=headers, files=files)
        if response.status_code == 200:
            scan_id = response.json()['data']['id']
            time.sleep(20)
            result_response = requests.get(f"{url_report}{scan_id}", headers=headers)
            if result_response.status_code == 200:
                result = result_response.json()['data']['attributes']
                return result['stats']['malicious'] == 0
        return False
    except Exception as e:
        print(f"خطأ في الفحص: {e}")
        return False

###############الواجهة#####

@SOLO.message_handler(commands=['start'])
def send_welcome(message):
    keyboard = InlineKeyboardMarkup()
    keyboard.add(InlineKeyboardButton("📂 رفع ملف", callback_data="upload_file"))
    keyboard.add(InlineKeyboardButton("📋 حالة البوت", callback_data="bot_status"))
    if str(message.from_user.id) == ADMIN_ID:
        keyboard.add(InlineKeyboardButton("🔧 لوحة تحكم المشرف", callback_data="admin_panel"))
    SOLO.send_message(message.chat.id, "مرحبًا بك! اختر أحد الخيارات:", reply_markup=keyboard)

@SOLO.callback_query_handler(func=lambda call: call.data == "upload_file")
def upload_prompt(call):
    SOLO.answer_callback_query(call.id)
    SOLO.send_message(call.message.chat.id, "📥 أرسل الملف الآن.")

@SOLO.callback_query_handler(func=lambda call: call.data == "bot_status")
def bot_status(call):
    if not uploaded_files:
        SOLO.answer_callback_query(call.id, "لا توجد ملفات.")
        return
    keyboard = InlineKeyboardMarkup()
    for file_name in uploaded_files:
        keyboard.add(InlineKeyboardButton(file_name, callback_data=f"manage_{file_name}"))
    SOLO.send_message(call.message.chat.id, "📋 الملفات:", reply_markup=keyboard)

@SOLO.message_handler(content_types=['document'])
def handle_file_upload(message):
    user_id = message.from_user.id
    file_info = SOLO.get_file(message.document.file_id)
    file_name = message.document.file_name

    if not file_name.endswith('.py'):
        SOLO.reply_to(message, "⚠️ فقط ملفات Python مسموحة!")
        return

    file_path = os.path.join(UPLOAD_FOLDER, file_name)
    downloaded_file = SOLO.download_file(file_info.file_path)
    with open(file_path, 'wb') as f:
        f.write(downloaded_file)

    SOLO.send_message(message.chat.id, "🔍 جاري الفحص...")
    if not scan(file_path):
        SOLO.reply_to(message, "⚠️ الملف يحتوي على مشاكل.")
        return

    uploaded_files[file_name] = {
        "path": file_path,
        "status": "مرفوع",
        "user_id": user_id,
    }
    keyboard = InlineKeyboardMarkup()
    keyboard.add(
        InlineKeyboardButton("▶️ تشغيل", callback_data=f"run_{file_name}"),
        InlineKeyboardButton("🛑 إيقاف", callback_data=f"stop_{file_name}"),
        InlineKeyboardButton("🗑️ حذف", callback_data=f"delete_{file_name}")
    )
    SOLO.send_message(message.chat.id, "✅ تم الرفع", reply_markup=keyboard)

@SOLO.callback_query_handler(func=lambda call: call.data.startswith("run_"))
def run_file(call):
    file_name = call.data.replace("run_", "")
    file_data = uploaded_files.get(file_name)
    if not file_data:
        return
    try:
        process = subprocess.Popen(["python3", file_data["path"]],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        file_data["status"] = "يعمل"
        if stdout:
            SOLO.send_message(call.message.chat.id, f"🖨️ الإخراج:\n\n{stdout}")
        if stderr:
            SOLO.send_message(call.message.chat.id, f"⚠️ خطأ:\n\n{stderr}")
    except Exception as e:
        SOLO.send_message(call.message.chat.id, f"❌ فشل التشغيل: {e}")

@SOLO.callback_query_handler(func=lambda call: call.data.startswith("stop_"))
def stop_file(call):
    file_name = call.data.replace("stop_", "")
    file_data = uploaded_files.get(file_name)
    file_data["status"] = "موقوف"
    SOLO.send_message(call.message.chat.id, f"🛑 تم إيقاف {file_name}")

@SOLO.callback_query_handler(func=lambda call: call.data.startswith("delete_"))
def delete_file(call):
    file_name = call.data.replace("delete_", "")
    file_data = uploaded_files.pop(file_name, None)
    if file_data:
        os.remove(file_data["path"])
    SOLO.send_message(call.message.chat.id, f"🗑️ تم الحذف: {file_name}")

###############تشغيل البوت###############

SOLO.infinity_polling()
