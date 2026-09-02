============================================
  WALLET DEMO — Flask + Razorpay Setup
============================================

STEP 1: Create your .env file
-------------------------------
Copy .env.example to .env:
  cp .env.example .env

Then open .env and fill in three values:

  RAZORPAY_KEY_ID     — from Razorpay Dashboard → Settings → API Keys → Test Mode
  RAZORPAY_KEY_SECRET — the secret paired with that key ID (click "Reveal Key Secret")
  INTERNAL_TOKEN      — any random string, e.g.:
                        python -c "import secrets; print(secrets.token_hex(32))"

STEP 2: Install dependencies
------------------------------
  pip install flask razorpay python-dotenv

STEP 3: Run the server
-----------------------
  python app.py

STEP 4: Open in browser
------------------------
  http://localhost:5000

STEP 5: Test credentials (use inside the Razorpay popup)
----------------------------------------------------------
  UPI Success : success@razorpay
  UPI Failure : failure@razorpay
  Card        : 4111 1111 1111 1111
  Expiry      : 12/26
  CVV         : 123
  OTP         : 1234

============================================
