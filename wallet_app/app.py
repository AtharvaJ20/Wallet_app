# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, send_from_directory
import razorpay
import hmac
import hashlib
import os
import functools
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal, ROUND_HALF_UP

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

# ── In-memory points-voucher balances (separate from wallet balance) ──
# key: voucher code, value: remaining points balance
voucher_balances = {}

DEMO_USER_ID = 'user_123'

def _seed_demo_vouchers() -> dict:
    """Seed three demo vouchers on every server start — one per voucher type.
    All reset with the server so the demo is always in a clean state.
    Returns {code: label} for /config.
    """
    now_utc = datetime.now(timezone.utc)
    expires = now_utc + timedelta(days=365)
    demos = [
        ('DEMO-20PCT', 'pct',    20,  '20% off'),
        ('SAVE50',     'fixed',  50,  '₹50 off'),
        ('EARN100',    'points', 100, '100 pts'),
    ]
    result = {}
    for code, dtype, dvalue, label in demos:
        vouchers[code] = {
            'code':           code,
            'user_id':        DEMO_USER_ID,
            'discount_type':  dtype,
            'discount_value': dvalue,
            'discount_pct':   dvalue if dtype == 'pct' else 0,
            'is_used':        False,
            'used_at':        None,
            'created_at':     now_utc,
            'expires_at':     expires,
        }
        result[code] = label
        print(f"[Demo] Voucher seeded: {code} ({label}, user={DEMO_USER_ID})")
    return result

DEMO_VOUCHERS     = _seed_demo_vouchers()
DEMO_VOUCHERS['POINTS2000']  = '2000 pts voucher'
voucher_balances['POINTS2000'] = 2000
DEMO_VOUCHER_CODE = 'DEMO-20PCT'  # kept for backward compat


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
        'razorpay_key_id':    RAZORPAY_KEY_ID,
        'internal_token':     INTERNAL_TOKEN,
        'demo_voucher_code':  DEMO_VOUCHER_CODE,
        'demo_voucher_codes': DEMO_VOUCHERS,
        'demo_user_id':       DEMO_USER_ID,
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
    data          = request.get_json(force=True)
    user_id       = data.get('user_id', '').strip()
    discount_type = data.get('discount_type', 'pct').strip().lower()
    # Accept discount_value or legacy discount_pct for pct type
    discount_value = data.get('discount_value') or data.get('discount_pct')
    expiry_days    = data.get('expiry_days', 30)

    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    if discount_type not in ('pct', 'fixed', 'points'):
        return jsonify({'error': "discount_type must be 'pct', 'fixed', or 'points'"}), 400

    try:
        discount_value = int(discount_value)
        expiry_days    = int(expiry_days)
    except (TypeError, ValueError):
        return jsonify({'error': 'discount_value and expiry_days must be integers'}), 400

    if discount_type == 'pct' and not (1 <= discount_value <= 100):
        return jsonify({'error': 'discount_value must be 1–100 for pct type'}), 400

    if discount_type in ('fixed', 'points') and discount_value < 1:
        return jsonify({'error': 'discount_value must be at least 1'}), 400

    if expiry_days < 1:
        return jsonify({'error': 'expiry_days must be at least 1'}), 400

    code       = f"DISC-{uuid.uuid4().hex[:8].upper()}"
    now_utc    = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(days=expiry_days)

    vouchers[code] = {
        'code':           code,
        'user_id':        user_id,
        'discount_type':  discount_type,
        'discount_value': discount_value,
        'discount_pct':   discount_value if discount_type == 'pct' else 0,
        'is_used':        False,
        'used_at':        None,
        'created_at':     now_utc,
        'expires_at':     expires_at,
    }

    print(f"[Voucher] Generated {code} | {discount_type}:{discount_value} | user={user_id} | expires={expires_at.isoformat()}")
    return jsonify({
        'code':           code,
        'user_id':        user_id,
        'discount_type':  discount_type,
        'discount_value': discount_value,
        'expires_at':     expires_at.isoformat(),
    }), 201


# ── Voucher: Redeem ──
@app.route('/redeem-voucher', methods=['POST'])
def redeem_voucher():
    data    = request.get_json(force=True)
    user_id = data.get('user_id', '').strip()
    code    = data.get('code', '').strip().upper()

    if not user_id or not code:
        return jsonify({'error': 'user_id and code are required'}), 400

    # Points-balance vouchers: deduct purchase_amount from the voucher's own pts balance
    # wallet['balance'] is never touched in this path
    if code in voucher_balances:
        try:
            purchase_amount = int(data.get('purchase_amount', 0))
        except (TypeError, ValueError):
            return jsonify({'error': 'purchase_amount is required for points_pay and must be an integer'}), 400
        if purchase_amount < 1:
            return jsonify({'error': 'purchase_amount must be at least 1'}), 400
        bal = voucher_balances[code]
        if bal < purchase_amount:
            return jsonify({'error': 'Insufficient voucher points', 'available': bal, 'required': purchase_amount}), 400
        voucher_balances[code] -= purchase_amount
        remaining = voucher_balances[code]
        wallet['transactions'].append({
            'type':    'debit',
            'amount':  purchase_amount,
            'desc':    f'Paid with voucher pts ({code})',
            'balance': wallet['balance'],
        })
        print(f"[Voucher] {code}: paid {purchase_amount} pts | {remaining} pts remaining on voucher")
        return jsonify({
            'code':             code,
            'discount_type':    'points_pay',
            'discount_value':   purchase_amount,
            'points_remaining': remaining,
            'voucher_balance':  remaining,
            'wallet_balance':   wallet['balance'],
            'valid':            True,
        }), 200


    voucher = vouchers.get(code)
    if voucher is None:
        return jsonify({'error': 'Voucher not found'}), 404

    if voucher['user_id'] != user_id:
        return jsonify({'error': 'Voucher not valid for this user'}), 403

    # Expiry is checked first so an expired code always returns 'expired',
    # regardless of its used state. This keeps response semantics unambiguous
    # for billing service retries (R-12).
    if datetime.now(timezone.utc) > voucher['expires_at']:
        return jsonify({'error': 'Voucher expired'}), 400

    # Idempotent: billing service may retry after a timeout
    if voucher['is_used']:
        print(f"[Voucher] {code} already redeemed by user={user_id}")
        return jsonify({
            'code':             code,
            'discount_pct':     voucher['discount_pct'],
            'already_redeemed': True,
        }), 200

    voucher['is_used'] = True
    voucher['used_at'] = datetime.now(timezone.utc)

    dtype  = voucher.get('discount_type', 'pct')
    dvalue = voucher.get('discount_value', voucher.get('discount_pct', 0))

    if dtype == 'points':
        wallet['balance'] += dvalue
        wallet['transactions'].append({
            'type':    'credit',
            'amount':  dvalue,
            'desc':    f'Points reward redeemed ({code})',
            'balance': wallet['balance'],
        })
        print(f"[Voucher] Points redeemed {code} | {dvalue} pts → ₹{dvalue} | user={user_id}")
        return jsonify({
            'code':            code,
            'discount_type':   'points',
            'discount_value':  dvalue,
            'points_credited': dvalue,
            'wallet_balance':  wallet['balance'],
            'valid':           True,
        }), 200

    print(f"[Voucher] Redeemed {code} | {dtype}:{dvalue} | user={user_id}")
    return jsonify({
        'code':           code,
        'discount_type':  dtype,
        'discount_value': dvalue,
        'discount_pct':   voucher.get('discount_pct', 0),
        'valid':          True,
    }), 200


# ── Voucher: Status ──
@app.route('/voucher-status', methods=['GET'])
def voucher_status():
    code    = request.args.get('code', '').strip().upper()
    user_id = request.args.get('user_id', '').strip()

    if not code or not user_id:
        return jsonify({'error': 'code and user_id query params are required'}), 400

    # Points-balance vouchers: have their own pts balance, separate from wallet
    if code in voucher_balances:
        bal = voucher_balances[code]
        if bal <= 0:
            return jsonify({'error': 'Voucher points exhausted', 'status': 'invalid'}), 400
        return jsonify({
            'status':         'valid',
            'discount_type':  'points_pay',
            'discount_value': bal,
            'expires_at':     None,
        }), 200


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
        'status':         'valid',
        'discount_type':  voucher.get('discount_type', 'pct'),
        'discount_value': voucher.get('discount_value', voucher.get('discount_pct', 0)),
        'discount_pct':   voucher.get('discount_pct', 0),
        'expires_at':     voucher['expires_at'].isoformat(),
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

        dtype  = voucher.get('discount_type', 'pct')
        dvalue = voucher.get('discount_value', voucher.get('discount_pct', 0))
        # Points are rewards, not billing discounts — skip in billing simulation
        if dtype == 'points':
            rejected.append({'code': code, 'reason': 'points_not_a_billing_discount'})
            continue
        applied.append({'code': code, 'discount_type': dtype, 'discount_value': dvalue,
                        'discount_pct': voucher.get('discount_pct', 0)})

    # Compute total discount. pct types stack additively (capped at 100%);
    # fixed types are summed as rupee amounts. Decimal arithmetic avoids float
    # rounding artefacts on unusual invoice amounts (B-15).
    _inv    = Decimal(str(invoice_amount))
    _two_dp = Decimal('0.01')

    total_pct_discount   = min(sum(v['discount_pct'] for v in applied if v['discount_type'] == 'pct'), 100)
    total_fixed_discount = sum(v['discount_value'] for v in applied if v['discount_type'] == 'fixed')

    pct_discount_amount   = (_inv * Decimal(str(total_pct_discount)) / 100).quantize(_two_dp, rounding=ROUND_HALF_UP)
    fixed_discount_amount = min(Decimal(str(total_fixed_discount)), _inv)
    discount_amount       = float(min(pct_discount_amount + fixed_discount_amount, _inv))
    final_amount          = float((_inv - Decimal(str(discount_amount))).quantize(_two_dp, rounding=ROUND_HALF_UP))
    total_discount_pct    = round(discount_amount / float(_inv) * 100, 2) if float(_inv) > 0 else 0

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
