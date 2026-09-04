# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, send_from_directory
import razorpay
import hmac
import hashlib
import os
import functools
import uuid
from datetime import datetime, timezone, timedelta

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

# ── In-memory voucher store (replace with DB in production) ──
# key: voucher code, value: voucher dict
vouchers = {}


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


# ── Voucher: Generate ──
@app.route('/generate-voucher', methods=['POST'])
@require_internal_token
def generate_voucher():
    data         = request.get_json(force=True)
    user_id      = data.get('user_id', '').strip()
    discount_pct = data.get('discount_pct')
    expiry_days  = data.get('expiry_days', 30)

    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    try:
        discount_pct = int(discount_pct)
        expiry_days  = int(expiry_days)
    except (TypeError, ValueError):
        return jsonify({'error': 'discount_pct and expiry_days must be integers'}), 400

    if not (1 <= discount_pct <= 100):
        return jsonify({'error': 'discount_pct must be between 1 and 100'}), 400

    if expiry_days < 1:
        return jsonify({'error': 'expiry_days must be at least 1'}), 400

    code       = f"DISC-{uuid.uuid4().hex[:8].upper()}"
    now_utc    = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(days=expiry_days)

    vouchers[code] = {
        'code':         code,
        'user_id':      user_id,
        'discount_pct': discount_pct,
        'is_used':      False,
        'used_at':      None,
        'created_at':   now_utc,
        'expires_at':   expires_at,
    }

    print(f"[Voucher] Generated {code} | {discount_pct}% | user={user_id} | expires={expires_at.isoformat()}")
    return jsonify({
        'code':         code,
        'user_id':      user_id,
        'discount_pct': discount_pct,
        'expires_at':   expires_at.isoformat(),
    }), 201


# ── Voucher: Redeem ──
@app.route('/redeem-voucher', methods=['POST'])
def redeem_voucher():
    data    = request.get_json(force=True)
    user_id = data.get('user_id', '').strip()
    code    = data.get('code', '').strip().upper()

    if not user_id or not code:
        return jsonify({'error': 'user_id and code are required'}), 400

    voucher = vouchers.get(code)
    if voucher is None:
        return jsonify({'error': 'Voucher not found'}), 404

    if voucher['user_id'] != user_id:
        return jsonify({'error': 'Voucher not valid for this user'}), 403

    # Idempotent: billing service may retry after a timeout
    if voucher['is_used']:
        print(f"[Voucher] {code} already redeemed by user={user_id}")
        return jsonify({
            'code':             code,
            'discount_pct':     voucher['discount_pct'],
            'already_redeemed': True,
        }), 200

    if datetime.now(timezone.utc) > voucher['expires_at']:
        return jsonify({'error': 'Voucher expired'}), 400

    voucher['is_used'] = True
    voucher['used_at'] = datetime.now(timezone.utc)

    print(f"[Voucher] Redeemed {code} | {voucher['discount_pct']}% | user={user_id}")
    return jsonify({
        'code':         code,
        'discount_pct': voucher['discount_pct'],
        'valid':        True,
    }), 200


# ── Voucher: Status ──
@app.route('/voucher-status', methods=['GET'])
def voucher_status():
    code    = request.args.get('code', '').strip().upper()
    user_id = request.args.get('user_id', '').strip()

    if not code or not user_id:
        return jsonify({'error': 'code and user_id query params are required'}), 400

    voucher = vouchers.get(code)
    if voucher is None:
        return jsonify({'status': 'not_found'}), 404

    if voucher['user_id'] != user_id:
        return jsonify({'error': 'Voucher not valid for this user'}), 403

    if voucher['is_used']:
        return jsonify({'status': 'used', 'discount_pct': voucher['discount_pct']}), 200

    if datetime.now(timezone.utc) > voucher['expires_at']:
        return jsonify({'status': 'expired', 'discount_pct': voucher['discount_pct']}), 200

    return jsonify({
        'status':       'valid',
        'discount_pct': voucher['discount_pct'],
        'expires_at':   voucher['expires_at'].isoformat(),
    }), 200


# ── Billing Simulation (replace with real billing service call in production) ──
# Stacking is additive: 10% + 15% = 25% off. Capped at 100%.
# Codes are validated but NOT marked used — simulation only.
@app.route('/simulate-billing', methods=['POST'])
def simulate_billing():
    data           = request.get_json(force=True)
    user_id        = data.get('user_id', '').strip()
    invoice_amount = data.get('invoice_amount')
    codes          = data.get('codes', [])

    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    try:
        invoice_amount = float(invoice_amount)
    except (TypeError, ValueError):
        return jsonify({'error': 'invoice_amount must be a number'}), 400

    if invoice_amount <= 0:
        return jsonify({'error': 'invoice_amount must be greater than 0'}), 400

    if not isinstance(codes, list):
        return jsonify({'error': 'codes must be a list'}), 400

    now_utc  = datetime.now(timezone.utc)
    applied  = []
    rejected = []

    for raw_code in codes:
        code    = str(raw_code).strip().upper()
        voucher = vouchers.get(code)

        if voucher is None:
            rejected.append({'code': code, 'reason': 'not_found'})
            continue

        if voucher['user_id'] != user_id:
            rejected.append({'code': code, 'reason': 'not_valid_for_user'})
            continue

        if voucher['is_used']:
            rejected.append({'code': code, 'reason': 'already_used'})
            continue

        if now_utc > voucher['expires_at']:
            rejected.append({'code': code, 'reason': 'expired'})
            continue

        applied.append({'code': code, 'discount_pct': voucher['discount_pct']})

    # Additive stacking, capped at 100%
    total_discount_pct = min(sum(v['discount_pct'] for v in applied), 100)
    discount_amount    = round(invoice_amount * total_discount_pct / 100, 2)
    final_amount       = round(invoice_amount - discount_amount, 2)

    print(f"[BillingSim] user={user_id} | invoice=₹{invoice_amount} | "
          f"discount={total_discount_pct}% | final=₹{final_amount} | "
          f"applied={[v['code'] for v in applied]} | rejected={[r['code'] for r in rejected]}")

    return jsonify({
        'original_amount':    invoice_amount,
        'total_discount_pct': total_discount_pct,
        'discount_amount':    discount_amount,
        'final_amount':       final_amount,
        'applied':            applied,
        'rejected':           rejected,
    }), 200


if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    print("=" * 50)
    print("  Wallet App running at http://localhost:5000")
    print("=" * 50)
    app.run(debug=debug, port=5000)
