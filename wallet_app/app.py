# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, send_from_directory
import razorpay
import hmac
import hashlib
import os
import functools

# Load .env file if python-dotenv is installed (optional dev convenience).
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__, static_folder='.')

# ── Razorpay Credentials (required env vars) ──
RAZORPAY_KEY_ID     = os.environ.get('RAZORPAY_KEY_ID', '')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', '')

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
    raise RuntimeError(
        'RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET must be set as environment variables. '
        'Copy .env.example to .env and fill in your values.'
    )

# ── Internal auth token for system endpoints ──
# Production: replace with proper session/JWT auth.
INTERNAL_TOKEN = os.environ.get('INTERNAL_TOKEN', '')

if not INTERNAL_TOKEN:
    raise RuntimeError(
        'INTERNAL_TOKEN must be set as an environment variable. '
        'Copy .env.example to .env and fill in a strong random value.'
    )

client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# ── In-memory wallet (replace with DB in production) ──
wallet = {'balance': 0, 'transactions': []}


def require_internal_token(fn):
    """Verify X-Internal-Token header on system endpoints.
    Production: replace with proper session/JWT auth.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get('X-Internal-Token', '')
        if not hmac.compare_digest(token, INTERNAL_TOKEN):
            return jsonify({'error': 'Forbidden'}), 403
        return fn(*args, **kwargs)
    return wrapper


# ── Serve frontend ──
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


# ── Expose config to frontend ──
# DEMO ONLY: returning INTERNAL_TOKEN to the browser is acceptable here because
# this is a single-user local demo. Production must use proper session/JWT auth
# instead of a shared secret visible in client-side code.
@app.route('/config')
def config():
    return jsonify({
        'razorpay_key_id': RAZORPAY_KEY_ID,
        'internal_token':  INTERNAL_TOKEN,
    })


# ── Step 1: Create Razorpay Order ──
@app.route('/create-order', methods=['POST'])
def create_order():
    data = request.json
    amount = int(data.get('amount', 0))

    if amount < 1:
        return jsonify({'error': 'Invalid amount'}), 400

    try:
        order = client.order.create({
            'amount': amount * 100,   # paise
            'currency': 'INR',
            'payment_capture': 1      # auto capture
        })
    except Exception as e:
        print(f"[Razorpay] Order creation failed: {e}")
        return jsonify({'error': f'Razorpay error: {e}'}), 502

    print(f"[Razorpay] Order created: {order['id']} for Rs.{amount}")
    return jsonify({'order_id': order['id'], 'amount': amount})


# ── Step 2: Verify Payment ──
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    data = request.json
    payment_id = data.get('razorpay_payment_id')
    order_id   = data.get('razorpay_order_id')
    signature  = data.get('razorpay_signature')
    amount     = int(data.get('amount', 0))

    if not payment_id or not order_id or not signature:
        return jsonify({'error': 'Missing payment fields'}), 400

    msg = f"{order_id}|{payment_id}"
    expected = hmac.new(
        bytes(RAZORPAY_KEY_SECRET, 'utf-8'),
        bytes(msg, 'utf-8'),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        print("[Security] Signature mismatch! Possible fraud.")
        return jsonify({'error': 'Invalid signature'}), 400

    wallet['balance'] += amount
    wallet['transactions'].append({
        'type':    'credit',
        'amount':  amount,
        'desc':    f'Added via Razorpay ({payment_id[-8:]})',
        'balance': wallet['balance']
    })

    print(f"[Wallet] Credited Rs.{amount} | Balance: Rs.{wallet['balance']}")
    return jsonify({'success': True, 'balance': wallet['balance']})


# ── Step 3: System Deduction ──
@app.route('/deduct', methods=['POST'])
@require_internal_token
def deduct():
    data   = request.json
    amount = int(data.get('amount', 0))
    reason = data.get('reason', 'System deduction')

    if amount < 1:
        return jsonify({'error': 'Invalid amount'}), 400

    if wallet['balance'] < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    wallet['balance'] -= amount
    wallet['transactions'].append({
        'type':    'debit',
        'amount':  amount,
        'desc':    reason,
        'balance': wallet['balance']
    })

    print(f"[Wallet] Deducted Rs.{amount} for '{reason}' | Balance: Rs.{wallet['balance']}")
    return jsonify({'success': True, 'balance': wallet['balance']})


# ── Step 4: Withdraw (simulate payout) ──
@app.route('/withdraw', methods=['POST'])
@require_internal_token
def withdraw():
    amount = wallet['balance']
    if amount <= 0:
        return jsonify({'error': 'Nothing to withdraw'}), 400

    wallet['transactions'].append({
        'type':    'debit',
        'amount':  amount,
        'desc':    'Withdrawn to bank account',
        'balance': 0
    })
    wallet['balance'] = 0

    print(f"[Wallet] Withdrawal of Rs.{amount} initiated (bank T+1)")
    return jsonify({'success': True, 'balance': 0})


# ── Get Balance & Transactions ──
@app.route('/balance', methods=['GET'])
def get_balance():
    return jsonify(wallet)


if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    print("=" * 50)
    print("  Wallet App running at http://localhost:5000")
    print("=" * 50)
    app.run(debug=debug, port=5000)
