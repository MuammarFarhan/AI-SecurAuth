import os
import pymysql
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev_secret_key')

# ─── Inject current_user ke semua template ────────────────────────────────────
class _User:
    """Objek sederhana yang merepresentasikan user dari session."""
    def __init__(self, data):
        self.id              = data.get('user_id')
        self.username        = data.get('username', '')
        self.nama            = data.get('nama', '')
        self.role            = data.get('role', '')
        self.is_authenticated = bool(self.id)

@app.context_processor
def inject_current_user():
    return dict(current_user=_User(session))

# ─── Database Helper ──────────────────────────────────────────────────────────
def get_db():
    return pymysql.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', ''),
        database=os.getenv('DB_NAME', 'ai_securauth'),
        port=int(os.getenv('DB_PORT', 3306)),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

def query(sql, params=None, fetchone=False, fetchall=False):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # Jika tidak ada params, jangan lewatkan tuple kosong
            # karena PyMySQL akan mencoba substitusi % pada SQL
            if params:
                cur.execute(sql, params)
            else:
                cur.execute(sql)
            if fetchone:  return cur.fetchone()
            if fetchall:  return cur.fetchall()
            return cur.lastrowid
    finally:
        conn.close()

# ─── Auth Decorator ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get('role') not in roles:
                flash('Akses ditolak. Hak akses tidak mencukupi.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ─── Helper ───────────────────────────────────────────────────────────────────
def log_audit(action, target_type=None, target_id=None, detail=None):
    try:
        query('''INSERT INTO audit_logs (user_id, action, target_type, target_id, detail, ip_address)
                 VALUES (%s, %s, %s, %s, %s, %s)''',
              (session.get('user_id'), action, target_type, target_id, detail, request.remote_addr))
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = query('SELECT * FROM users WHERE username=%s AND is_active=1', (username,), fetchone=True)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['nama'] = user['nama']
            session['role'] = user['role']
            query('UPDATE users SET last_login=%s WHERE id=%s', (datetime.now(), user['id']))
            log_audit('login', 'users', str(user['id']), f"Login berhasil: {username}")
            flash(f"Selamat datang, {user['nama']}!", 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah!', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    log_audit('logout', 'users', str(session.get('user_id')))
    session.clear()
    flash('Anda telah berhasil keluar.', 'info')
    return redirect(url_for('login'))

# ═══════════════════════════════════════════════════════════════════════════════
# [1] DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/')
@login_required
def dashboard():
    total_logins  = query('SELECT COUNT(*) AS c FROM login_logs', fetchone=True)['c']
    total_ato     = query('SELECT COUNT(*) AS c FROM login_logs WHERE is_account_takeover=1', fetchone=True)['c']
    total_blocked = query('SELECT COUNT(*) AS c FROM login_logs WHERE ai_decision="block"', fetchone=True)['c']
    total_mfa     = query('SELECT COUNT(*) AS c FROM login_logs WHERE ai_decision="challenge_mfa"', fetchone=True)['c']
    total_allow   = query('SELECT COUNT(*) AS c FROM login_logs WHERE ai_decision="allow"', fetchone=True)['c']
    total_attack_ip = query('SELECT COUNT(*) AS c FROM login_logs WHERE is_attack_ip=1', fetchone=True)['c']
    open_incidents  = query('SELECT COUNT(*) AS c FROM incidents WHERE status IN ("open","investigating")', fetchone=True)['c']

    # Distribusi keputusan AI
    decision_data = [total_allow, total_mfa, total_blocked]

    # Login per jam (12 jam terakhir)
    hourly = query('''
        SELECT DATE_FORMAT(timestamp, '%H:00') AS jam, COUNT(*) AS total
        FROM login_logs
        WHERE timestamp >= NOW() - INTERVAL 12 HOUR
        GROUP BY jam ORDER BY jam
    ''', fetchall=True)

    # Top 5 negara serangan
    top_threats = query('''
        SELECT country, COUNT(*) as cnt FROM login_logs 
        WHERE is_account_takeover=1 AND country IS NOT NULL
        GROUP BY country ORDER BY cnt DESC LIMIT 5
    ''', fetchall=True)

    # Data peta (geo)
    geo_data = query('''
        SELECT latitude, longitude, country, ai_decision, risk_score
        FROM login_logs WHERE latitude IS NOT NULL LIMIT 200
    ''', fetchall=True)

    return render_template('dashboard.html',
        total_logins=total_logins, total_ato=total_ato, total_blocked=total_blocked,
        total_mfa=total_mfa, total_allow=total_allow, total_attack_ip=total_attack_ip,
        open_incidents=open_incidents, decision_data=decision_data,
        hourly=hourly, top_threats=top_threats, geo_data=geo_data
    )

# ═══════════════════════════════════════════════════════════════════════════════
# [2] LIVE LOGIN MONITOR
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/monitor')
@login_required
def monitor():
    page      = request.args.get('page', 1, type=int)
    per_page  = request.args.get('per_page', 25, type=int)
    risk      = request.args.get('risk', 'all')
    decision  = request.args.get('decision', 'all')
    search    = request.args.get('search', '').strip()

    conditions = []
    params = []
    if risk in ('low','medium','high'):
        conditions.append('risk_level = %s'); params.append(risk)
    if decision in ('allow','challenge_mfa','block'):
        conditions.append('ai_decision = %s'); params.append(decision)
    if search:
        conditions.append('(ip_address LIKE %s OR user_id_target LIKE %s OR country LIKE %s)')
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
    where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''

    total = query(f'SELECT COUNT(*) AS c FROM login_logs {where}', params, fetchone=True)['c']
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page

    logs = query(f'''SELECT * FROM login_logs {where} ORDER BY timestamp DESC LIMIT %s OFFSET %s''',
                 params + [per_page, offset], fetchall=True)

    return render_template('monitor.html',
        logs=logs, page=page, per_page=per_page, total=total, total_pages=total_pages,
        risk=risk, decision=decision, search=search
    )

@app.route('/api/monitor/latest')
@login_required
def api_latest_logs():
    logs = query('''SELECT id, timestamp, user_id_target, ip_address, country, device_type,
                           rtt_ms, risk_score, risk_level, ai_decision, is_attack_ip, is_account_takeover
                    FROM login_logs ORDER BY timestamp DESC LIMIT 10''', fetchall=True)
    for log in logs:
        if log['timestamp']:
            log['timestamp'] = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
    return jsonify(logs)

@app.route('/api/monitor/export')
@login_required
def export_logs():
    import csv, io
    logs = query('SELECT * FROM login_logs ORDER BY timestamp DESC', fetchall=True)
    output = io.StringIO()
    if logs:
        writer = csv.DictWriter(output, fieldnames=logs[0].keys())
        writer.writeheader()
        for row in logs:
            writer.writerow({k: (v.strftime('%Y-%m-%d %H:%M:%S') if isinstance(v, datetime) else v) for k, v in row.items()})
    from flask import Response
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=login_logs_export.csv'})

# ═══════════════════════════════════════════════════════════════════════════════
# [3] AI RISK ASSESSMENT & SIMULATOR
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/simulator')
@login_required
def simulator():
    policy = query('SELECT * FROM policy_thresholds ORDER BY id DESC LIMIT 1', fetchone=True)
    return render_template('simulator.html', policy=policy)

@app.route('/api/simulate', methods=['POST'])
@login_required
def api_simulate():
    try:
        data = request.get_json()
        ip_address   = data.get('ip_address', '0.0.0.0')
        asn          = data.get('asn', '')
        country      = data.get('country', 'Unknown')
        device_type  = data.get('device_type', 'desktop')
        os_name      = data.get('os', 'Unknown')
        browser      = data.get('browser', 'Unknown')
        rtt_ms       = int(data.get('rtt_ms', 100))
        is_attack_ip = int(data.get('is_attack_ip', 0))
        model_choice = data.get('model', 'xgboost')

        # Simulasi Rule-Based + Feature Scoring
        score = 0.0
        feature_contributions = []

        # Rule: Attack IP langsung blokir
        if is_attack_ip:
            score += 50.0
            feature_contributions.append({"feature": "is_attack_ip", "contribution": 50.0,
                                           "note": "IP terdaftar sebagai penyerang (+50%)"})
        # Rule: RTT
        if rtt_ms > 3000:
            delta = 30.0
            score += delta
            feature_contributions.append({"feature": "rtt_ms", "contribution": delta,
                                           "note": f"RTT sangat tinggi: {rtt_ms}ms > 3000ms threshold (+{delta}%)"})
        elif rtt_ms > 1500:
            delta = 15.0
            score += delta
            feature_contributions.append({"feature": "rtt_ms", "contribution": delta,
                                           "note": f"RTT tinggi: {rtt_ms}ms > 1500ms (+{delta}%)"})
        # Rule: Negara berisiko tinggi
        HIGH_RISK_COUNTRIES = ['Russia','Ukraine','North Korea','Iran','Belarus']
        if country in HIGH_RISK_COUNTRIES:
            delta = 20.0
            score += delta
            feature_contributions.append({"feature": "country", "contribution": delta,
                                           "note": f"{country} masuk daftar negara berisiko tinggi (+{delta}%)"})
        # Rule: Browser lawas
        if 'IE 11' in browser or 'IE11' in browser:
            delta = 10.0
            score += delta
            feature_contributions.append({"feature": "browser", "contribution": delta,
                                           "note": "Browser sangat lawas (IE11) — jarang digunakan user sah (+10%)"})
        # Base score acak-ish berdasarkan kombinasi
        import hashlib
        combo_hash = int(hashlib.md5(f"{ip_address}{asn}{country}".encode()).hexdigest()[:4], 16)
        base = (combo_hash % 25)  # 0-24
        score += base
        if base > 0:
            feature_contributions.append({"feature": "telemetry_baseline", "contribution": float(base),
                                           "note": f"Skor baseline dari kombinasi telemetri IP/ASN/Lokasi (+{base}%)"})

        score = min(score, 100.0)

        # Tentukan keputusan
        policy = query('SELECT * FROM policy_thresholds ORDER BY id DESC LIMIT 1', fetchone=True)
        mfa_t  = float(policy['mfa_threshold'])  if policy else 30.0
        blk_t  = float(policy['block_threshold']) if policy else 70.0

        if score >= blk_t:
            decision = 'block'
            risk_level = 'high'
        elif score >= mfa_t:
            decision = 'challenge_mfa'
            risk_level = 'medium'
        else:
            decision = 'allow'
            risk_level = 'low'

        log_audit('simulate', 'simulator', None,
                  f"Simulasi: IP={ip_address}, Skor={score:.1f}%, Keputusan={decision}")

        return jsonify({
            'success': True,
            'score': round(score, 2),
            'risk_level': risk_level,
            'decision': decision,
            'model_used': model_choice,
            'contributions': feature_contributions
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ═══════════════════════════════════════════════════════════════════════════════
# [4] THREAT & INCIDENT INVESTIGATION
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/incidents')
@login_required
def incidents():
    status_filter = request.args.get('status', 'all')
    conditions = []
    params = []
    if status_filter != 'all':
        conditions.append('i.status = %s'); params.append(status_filter)
    where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''

    inc_list = query(f'''
        SELECT i.*, l.ip_address, l.country, l.risk_score, l.timestamp AS login_time,
               u.nama AS assignee_name
        FROM incidents i
        JOIN login_logs l ON l.id = i.log_id
        LEFT JOIN users u ON u.id = i.assigned_to
        {where} ORDER BY i.created_at DESC
    ''', params, fetchall=True)

    return render_template('incidents.html', incidents=inc_list, status_filter=status_filter)

@app.route('/incidents/<int:inc_id>')
@login_required
def incident_detail(inc_id):
    inc = query('''
        SELECT i.*, l.*, u.nama AS assignee_name
        FROM incidents i JOIN login_logs l ON l.id=i.log_id
        LEFT JOIN users u ON u.id=i.assigned_to
        WHERE i.id=%s
    ''', (inc_id,), fetchone=True)
    if not inc:
        flash('Insiden tidak ditemukan.', 'danger')
        return redirect(url_for('incidents'))

    actions = query('SELECT ia.*, u.nama FROM incident_actions ia LEFT JOIN users u ON u.id=ia.executed_by WHERE ia.incident_id=%s ORDER BY ia.executed_at DESC', (inc_id,), fetchall=True)
    analysts = query("SELECT id, nama FROM users WHERE role != 'auditor' AND is_active=1", fetchall=True)
    return render_template('incident_detail.html', inc=inc, actions=actions, analysts=analysts)

@app.route('/incidents/<int:inc_id>/action', methods=['POST'])
@login_required
def incident_action(inc_id):
    action_type = request.form.get('action_type')
    note        = request.form.get('note', '')
    allowed     = ['revoke_session','force_reset_password','lock_account','unlock_account','add_note']
    if action_type not in allowed:
        return jsonify({'success': False, 'error': 'Invalid action'})
    query('INSERT INTO incident_actions (incident_id, action_type, note, executed_by) VALUES (%s,%s,%s,%s)',
          (inc_id, action_type, note, session['user_id']))
    log_audit('incident_action', 'incidents', str(inc_id), f"Aksi: {action_type}")
    return jsonify({'success': True, 'message': f'Aksi "{action_type}" berhasil dijalankan.'})

@app.route('/incidents/<int:inc_id>/status', methods=['POST'])
@login_required
def update_incident_status(inc_id):
    new_status = request.form.get('status')
    if new_status not in ('open','investigating','resolved','false_positive'):
        return jsonify({'success': False, 'error': 'Status tidak valid'})
    resolved_at = 'NOW()' if new_status == 'resolved' else 'NULL'
    query(f'UPDATE incidents SET status=%s, resolved_at={resolved_at} WHERE id=%s', (new_status, inc_id))
    query('INSERT INTO incident_actions (incident_id, action_type, note, executed_by) VALUES (%s,"status_change",%s,%s)',
          (inc_id, f'Status diubah ke: {new_status}', session['user_id']))
    log_audit('update_incident_status', 'incidents', str(inc_id), f"Status → {new_status}")
    return jsonify({'success': True, 'message': f'Status insiden diperbarui ke "{new_status}".'})

# ═══════════════════════════════════════════════════════════════════════════════
# [5] MODEL MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/models')
@login_required
def models():
    metrics = query('SELECT * FROM model_metrics ORDER BY trained_at DESC', fetchall=True)
    return render_template('models.html', metrics=metrics)

@app.route('/api/models/switch', methods=['POST'])
@login_required
@role_required('security_engineer')
def switch_model():
    model_name = request.form.get('model_name', '').lower().replace(' ', '_')
    if model_name not in ('xgboost', 'random_forest'):
        return jsonify({'success': False, 'error': 'Model tidak valid'})
    query('UPDATE policy_thresholds SET active_model=%s WHERE id=1', (model_name,))
    log_audit('switch_model', 'policy_thresholds', '1', f'Model aktif diubah ke: {model_name}')
    return jsonify({'success': True, 'message': f'Model aktif diubah ke {model_name}.'})

# ═══════════════════════════════════════════════════════════════════════════════
# [6] ADAPTIVE POLICY & RULE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/policy')
@login_required
def policy():
    thresholds = query('SELECT * FROM policy_thresholds ORDER BY id DESC LIMIT 1', fetchone=True)
    rules      = query('SELECT pr.*, u.nama FROM policy_rules pr LEFT JOIN users u ON u.id=pr.created_by ORDER BY pr.id DESC', fetchall=True)
    return render_template('policy.html', thresholds=thresholds, rules=rules)

@app.route('/api/policy/thresholds', methods=['POST'])
@login_required
@role_required('security_engineer')
def update_thresholds():
    mfa_t = request.form.get('mfa_threshold', 30, type=float)
    blk_t = request.form.get('block_threshold', 70, type=float)
    mode  = request.form.get('operation_mode', 'active')
    query('UPDATE policy_thresholds SET mfa_threshold=%s, block_threshold=%s, operation_mode=%s, updated_by=%s WHERE id=1',
          (mfa_t, blk_t, mode, session['user_id']))
    log_audit('change_threshold', 'policy_thresholds', '1', f'MFA:{mfa_t}% Block:{blk_t}%')
    return jsonify({'success': True, 'message': 'Konfigurasi ambang batas berhasil disimpan.'})

@app.route('/api/policy/rules', methods=['POST'])
@login_required
@role_required('security_engineer')
def add_rule():
    r = request.form
    query('''INSERT INTO policy_rules (rule_name, condition_field, condition_op, condition_value, action, score_delta, created_by)
             VALUES (%s,%s,%s,%s,%s,%s,%s)''',
          (r.get('rule_name'), r.get('condition_field'), r.get('condition_op'),
           r.get('condition_value'), r.get('action'), r.get('score_delta') or None, session['user_id']))
    log_audit('add_rule', 'policy_rules', None, f"Aturan baru: {r.get('rule_name')}")
    return jsonify({'success': True, 'message': 'Aturan keamanan berhasil ditambahkan.'})

@app.route('/api/policy/rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
@role_required('security_engineer')
def toggle_rule(rule_id):
    rule = query('SELECT is_active FROM policy_rules WHERE id=%s', (rule_id,), fetchone=True)
    if not rule:
        return jsonify({'success': False, 'error': 'Aturan tidak ditemukan'})
    new_state = 0 if rule['is_active'] else 1
    query('UPDATE policy_rules SET is_active=%s WHERE id=%s', (new_state, rule_id))
    log_audit('toggle_rule', 'policy_rules', str(rule_id), f'Status → {"Aktif" if new_state else "Nonaktif"}')
    return jsonify({'success': True, 'is_active': new_state})

@app.route('/api/policy/rules/<int:rule_id>', methods=['DELETE'])
@login_required
@role_required('security_engineer')
def delete_rule(rule_id):
    query('DELETE FROM policy_rules WHERE id=%s', (rule_id,))
    log_audit('delete_rule', 'policy_rules', str(rule_id))
    return jsonify({'success': True, 'message': 'Aturan dihapus.'})

# ═══════════════════════════════════════════════════════════════════════════════
# [7] USER & DEVICE REPUTATION
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/reputation')
@login_required
def reputation():
    whitelist = query("SELECT * FROM ip_reputation WHERE type='whitelist' ORDER BY created_at DESC", fetchall=True)
    blacklist = query("SELECT * FROM ip_reputation WHERE type='blacklist' ORDER BY created_at DESC", fetchall=True)
    return render_template('reputation.html', whitelist=whitelist, blacklist=blacklist)

@app.route('/api/reputation', methods=['POST'])
@login_required
@role_required('security_engineer','soc_analyst')
def add_reputation():
    rep_type    = request.form.get('type')
    entry_value = request.form.get('entry_value', '').strip()
    entry_type  = request.form.get('entry_type', 'ip')
    reason      = request.form.get('reason', '')
    if not entry_value or rep_type not in ('whitelist', 'blacklist'):
        return jsonify({'success': False, 'error': 'Data tidak lengkap'})
    try:
        query('INSERT INTO ip_reputation (type, entry_value, entry_type, reason, added_by) VALUES (%s,%s,%s,%s,%s)',
              (rep_type, entry_value, entry_type, reason, session['user_id']))
        log_audit(f'add_{rep_type}', 'ip_reputation', None, f'{rep_type}: {entry_value}')
        return jsonify({'success': True, 'message': f'Entri {rep_type} berhasil ditambahkan.'})
    except Exception as e:
        return jsonify({'success': False, 'error': 'Entri sudah ada atau terjadi kesalahan.'})

@app.route('/api/reputation/<int:rep_id>', methods=['DELETE'])
@login_required
@role_required('security_engineer')
def delete_reputation(rep_id):
    query('DELETE FROM ip_reputation WHERE id=%s', (rep_id,))
    log_audit('delete_reputation', 'ip_reputation', str(rep_id))
    return jsonify({'success': True, 'message': 'Entri berhasil dihapus.'})

# ═══════════════════════════════════════════════════════════════════════════════
# [8] SETTINGS & AUDIT TRAIL
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/settings')
@login_required
@role_required('security_engineer')
def settings():
    users_list = query('SELECT * FROM users ORDER BY created_at DESC', fetchall=True)
    return render_template('settings.html', users_list=users_list)

@app.route('/audit')
@login_required
def audit():
    logs = query('''SELECT al.*, u.username, u.nama FROM audit_logs al
                    LEFT JOIN users u ON u.id=al.user_id
                    ORDER BY al.created_at DESC LIMIT 200''', fetchall=True)
    return render_template('audit.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)

