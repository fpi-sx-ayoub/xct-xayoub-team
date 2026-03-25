# XCT xAyOuB API

Flask API لخدمة تتبع حالة اللاعبين.

## المتطلبات

- Python 3.8+
- pip

## التثبيت

```bash
pip install -r requirements.txt
```

## التشغيل المحلي

```bash
python app.py
```

سيتم تشغيل الخادم على `http://localhost:5000`

## نقاط النهاية (Endpoints)

### GET /s
الحصول على حالة اللاعب

**المعاملات:**
- `uid` (مطلوب): معرف اللاعب

**مثال:**
```
GET /s?uid=123456789
```

**الرد:**
```json
{
  "uid": "123456789",
  "status": "ONLINE",
  "mode": "BERMUDA"
}
```

## النشر على Railway

1. ادفع الكود إلى GitHub
2. اربط المستودع مع Railway
3. عيّن متغيرات البيئة إذا لزم الأمر
4. سيتم النشر تلقائياً

## الترخيص

MIT
