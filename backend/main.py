from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
import sqlite3
import json
import os
from crypto_core import CustomRSA, CustomECC, CustomHMAC, PasswordAuth, TwoFactorAuth, SessionManager, CustomHash
from typing import List, Optional

app = FastAPI()

def get_db():
    conn = sqlite3.connect('database.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.commit()
        conn.close()

def load_keystore():
    if os.path.exists('keystore.json'):
        with open('keystore.json', 'r') as f:
            return json.load(f)
    return {}

def save_keystore(store):
    with open('keystore.json', 'w') as f:
        json.dump(store, f)

def init_db():
    with sqlite3.connect('database.db', check_same_thread=False) as conn:
        conn.row_factory = sqlite3.Row
        with open('schema.sql') as f:
            conn.executescript(f.read())
        
        cur = conn.cursor()
        # Admin Email: admin@university.edu
        # Admin Password: adminPassword123
        admin_hash = CustomHash.hash('admin@university.edu')
        cur.execute("SELECT id FROM users WHERE username_hash = ?", (admin_hash,))
        admin = cur.fetchone()
        
        store = load_keystore()
        
        if not admin or (admin and str(admin['id']) not in store):
            pwd_hash, salt = PasswordAuth.hash_password('adminPassword123')
            rsa_pub, rsa_priv = CustomRSA.generate_keys(256)
            ecc_pub, ecc_priv = CustomECC.generate_keys()
            
            if admin:
                cur.execute("DELETE FROM users WHERE id = ?", (admin['id'],))
                
            cur.execute("""
                INSERT INTO users (username_hash, role, password_hash, salt, public_key_rsa, public_key_ecc)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (admin_hash, 'admin', pwd_hash, salt, json.dumps(rsa_pub), json.dumps(ecc_pub)))
            admin_id = cur.lastrowid
            
            store[str(admin_id)] = {
                'rsa_priv': rsa_priv, 'rsa_pub': rsa_pub,
                'ecc_priv': ecc_priv, 'ecc_pub': ecc_pub
            }
            save_keystore(store)

init_db()

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.split(" ")[1]
    try:
        data = SessionManager.verify_token(token)
        return data
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

class RegisterRequest(BaseModel):
    email: str
    password: str
    role: str
    student_id: Optional[str] = None
    student_name: Optional[str] = None
    student_contact: Optional[str] = None
    proctor_id: Optional[str] = None
    proctor_name: Optional[str] = None

class LoginRequest(BaseModel):
    email: str
    password: str
    otp: str

class ReportRequest(BaseModel):
    report_content: str
    attachment_data: Optional[str] = None

class AssignRequest(BaseModel):
    report_id: int
    auditor_id: int

class ValidateRequest(BaseModel):
    feedback: str

class DecisionRequest(BaseModel):
    decision: str

class ProfileUpdateRequest(BaseModel):
    profile_data: str
    new_email: str = None

@app.post("/2fa/send")
def send_otp(req: dict):
    email = req.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    TwoFactorAuth.generate_otp(email)
    return {"message": "Verification code sent to your email"}

@app.post("/register")
def register(req: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    if req.role == 'admin':
        raise HTTPException(status_code=400, detail="Cannot register as admin")
        
    if req.role == 'reporter':
        if not req.email.endswith('@g.bracu.ac.bd'):
            raise HTTPException(status_code=400, detail="Reporters must use @g.bracu.ac.bd email")
        profile_data = f"Name: {req.student_name}, ID: {req.student_id}, Contact: {req.student_contact}, Email: {req.email}"
    elif req.role == 'auditor':
        profile_data = f"Name: {req.proctor_name}, Proctor ID: {req.proctor_id}, Email: {req.email}"
    else:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    cur = db.cursor()
    uname_hash = CustomHash.hash(req.email)
    cur.execute("SELECT id FROM users WHERE username_hash = ?", (uname_hash,))
    if cur.fetchone():
        raise HTTPException(status_code=400, detail="User email already exists")

    pwd_hash, salt = PasswordAuth.hash_password(req.password)
    rsa_pub, rsa_priv = CustomRSA.generate_keys(256)
    ecc_pub, ecc_priv = CustomECC.generate_keys()

    cur.execute("SELECT public_key_ecc FROM users WHERE role = 'admin'")
    admin_ecc_pub = json.loads(cur.fetchone()['public_key_ecc'])
    encrypted_profile = CustomECC.encrypt(profile_data, tuple(admin_ecc_pub))
    
    cur.execute("""
        INSERT INTO users (username_hash, role, password_hash, salt, profile_data_encrypted, public_key_rsa, public_key_ecc)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (uname_hash, req.role, pwd_hash, salt, json.dumps(encrypted_profile), json.dumps(rsa_pub), json.dumps(ecc_pub)))
    user_id = cur.lastrowid
    
    store = load_keystore()
    store[str(user_id)] = {
        'rsa_priv': rsa_priv, 'rsa_pub': rsa_pub,
        'ecc_priv': ecc_priv, 'ecc_pub': ecc_pub
    }
    save_keystore(store)
    
    return {"message": "User registered successfully"}

@app.post("/login")
def login(req: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    if not TwoFactorAuth.verify_otp(req.email, req.otp):
        raise HTTPException(status_code=401, detail="Invalid or expired 2FA code")

    cur = db.cursor()
    uname_hash = CustomHash.hash(req.email)
    cur.execute("SELECT id, role, password_hash, salt FROM users WHERE username_hash = ?", (uname_hash,))
    user = cur.fetchone()
    
    if not user or not PasswordAuth.verify(req.password, user['password_hash'], user['salt']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    token = SessionManager.create_token(user['id'], user['role'])
    return {"message": "Login successful", "token": token, "role": user['role'], "email": req.email}

@app.post("/reports")
def submit_report(req: ReportRequest, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'reporter':
        raise HTTPException(status_code=403, detail="Only reporters can submit")

    cur = db.cursor()
    cur.execute("SELECT public_key_rsa FROM users WHERE role = 'admin'")
    admin_rsa_pub = json.loads(cur.fetchone()['public_key_rsa'])
    
    encrypted_content = CustomRSA.encrypt(req.report_content, tuple(admin_rsa_pub))
    signature = CustomHMAC.compute("shared_secret_key", req.report_content)
    
    encrypted_attachment = None
    if req.attachment_data:
        encrypted_attachment = CustomRSA.encrypt(req.attachment_data, tuple(admin_rsa_pub))
    
    cur.execute("""
        INSERT INTO reports (reporter_id, report_content_encrypted, attachment_encrypted, hmac_signature)
        VALUES (?, ?, ?, ?)
    """, (current_user['user_id'], json.dumps(encrypted_content), json.dumps(encrypted_attachment) if encrypted_attachment else None, signature))
    
    return {"message": "Report submitted securely"}

@app.get("/reports")
def get_reports(db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    cur = db.cursor()
    store = load_keystore()
    my_keys = store.get(str(current_user['user_id']))

    if current_user['role'] == 'admin':
        cur.execute("SELECT reports.*, users.profile_data_encrypted FROM reports JOIN users ON reports.reporter_id = users.id")
        reports = [dict(r) for r in cur.fetchall()]
        for r in reports:
            # Decrypt reporter profile using Admin ECC key
            print("Decrypting reporter profile...")
            try:
                profile = CustomECC.decrypt(json.loads(r['profile_data_encrypted']), my_keys['ecc_priv'])
                print("Profile decrypted:", profile)
                r['reporter_profile'] = profile
                r['reporter_name'] = profile.split(',')[0].replace('Name: ', '').strip()
            except Exception as e:
                print("ECC Decrypt Error:", e)
                r['reporter_profile'] = "Unknown"
                r['reporter_name'] = "Unknown"
                
            # Decrypt for admin view
            try:
                r['decrypted_content'] = CustomRSA.decrypt(json.loads(r['report_content_encrypted']), tuple(my_keys['rsa_priv']))
                if r['attachment_encrypted']:
                    r['has_attachment'] = True
                else:
                    r['has_attachment'] = False
            except Exception as e:
                print("RSA Decrypt Error:", e)
                r['decrypted_content'] = "Decryption failed"
        return reports
        
    elif current_user['role'] == 'auditor':
        cur.execute("SELECT * FROM reports WHERE assigned_auditor_id = ?", (current_user['user_id'],))
        reports = [dict(r) for r in cur.fetchall()]
        for r in reports:
            # Decrypt using auditor's key
            try:
                r['decrypted_content'] = CustomRSA.decrypt(json.loads(r['report_content_encrypted']), tuple(my_keys['rsa_priv']))
                if r['attachment_encrypted']:
                    r['has_attachment'] = True
                else:
                    r['has_attachment'] = False
            except:
                r['decrypted_content'] = "Decryption failed"
        return reports
        
    elif current_user['role'] == 'reporter':
        cur.execute("SELECT * FROM reports WHERE reporter_id = ?", (current_user['user_id'],))
        return [dict(r) for r in cur.fetchall()]
    raise HTTPException(status_code=403, detail="Invalid role")

@app.get("/reports/{report_id}/attachment")
def get_attachment(report_id: int, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    cur = db.cursor()
    cur.execute("SELECT attachment_encrypted, assigned_auditor_id FROM reports WHERE id = ?", (report_id,))
    report = cur.fetchone()
    if not report or not report['attachment_encrypted']:
        raise HTTPException(status_code=404, detail="No attachment")
        
    if current_user['role'] == 'auditor' and report['assigned_auditor_id'] != current_user['user_id']:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    store = load_keystore()
    my_keys = store.get(str(current_user['user_id']))
    
    try:
        decrypted_attachment = CustomRSA.decrypt(json.loads(report['attachment_encrypted']), tuple(my_keys['rsa_priv']))
        return {"attachment": decrypted_attachment}
    except:
        raise HTTPException(status_code=500, detail="Failed to decrypt attachment")

@app.get("/auditors")
def get_auditors(db: sqlite3.Connection = Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT id, profile_data_encrypted FROM users WHERE role = 'auditor'")
    auditor_rows = cur.fetchall()
    
    auditors = []
    # Fetch admin keys to decrypt the names
    cur.execute("SELECT id FROM users WHERE role = 'admin'")
    admin = cur.fetchone()
    store = load_keystore()
    admin_keys = store.get(str(admin['id']))
    
    for row in auditor_rows:
        try:
            profile = CustomECC.decrypt(json.loads(row['profile_data_encrypted']), admin_keys['ecc_priv'])
            name = profile.split(',')[0].replace('Name: ', '')
            auditors.append({"id": row['id'], "name": name, "profile": profile})
        except:
            auditors.append({"id": row['id'], "name": "Unknown Proctor", "profile": "Unknown"})
    return auditors

@app.get("/reporters")
def get_reporters(db: sqlite3.Connection = Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT id, profile_data_encrypted FROM users WHERE role = 'reporter'")
    reporter_rows = cur.fetchall()
    
    reporters = []
    # Fetch admin keys to decrypt the names
    cur.execute("SELECT id FROM users WHERE role = 'admin'")
    admin = cur.fetchone()
    store = load_keystore()
    admin_keys = store.get(str(admin['id']))
    
    for row in reporter_rows:
        try:
            profile = CustomECC.decrypt(json.loads(row['profile_data_encrypted']), admin_keys['ecc_priv'])
            name = profile.split(',')[0].replace('Name: ', '')
            reporters.append({"id": row['id'], "name": name, "profile": profile})
        except:
            reporters.append({"id": row['id'], "name": "Unknown Student", "profile": "Unknown"})
    return reporters

@app.post("/reports/assign")
def assign_report(req: AssignRequest, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Only admin can assign")
        
    cur = db.cursor()
    cur.execute("SELECT report_content_encrypted, attachment_encrypted FROM reports WHERE id = ?", (req.report_id,))
    report = cur.fetchone()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    store = load_keystore()
    admin_keys = store.get(str(current_user['user_id']))
    
    decrypted_content = CustomRSA.decrypt(json.loads(report['report_content_encrypted']), tuple(admin_keys['rsa_priv']))
    
    cur.execute("SELECT public_key_rsa FROM users WHERE id = ?", (req.auditor_id,))
    auditor = cur.fetchone()
    auditor_rsa_pub = json.loads(auditor['public_key_rsa'])
    
    re_encrypted_content = CustomRSA.encrypt(decrypted_content, tuple(auditor_rsa_pub))
    
    re_encrypted_attachment = None
    if report['attachment_encrypted']:
        dec_att = CustomRSA.decrypt(json.loads(report['attachment_encrypted']), tuple(admin_keys['rsa_priv']))
        re_encrypted_attachment = CustomRSA.encrypt(dec_att, tuple(auditor_rsa_pub))
    
    cur.execute("""
        UPDATE reports SET assigned_auditor_id = ?, status = 'assigned', report_content_encrypted = ?, attachment_encrypted = ?
        WHERE id = ?
    """, (req.auditor_id, json.dumps(re_encrypted_content), json.dumps(re_encrypted_attachment) if re_encrypted_attachment else None, req.report_id))
    
    return {"message": "Report assigned and securely re-encrypted for Auditor"}

@app.post("/reports/{report_id}/validate")
def validate_report(report_id: int, req: ValidateRequest, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'auditor':
        raise HTTPException(status_code=403, detail="Only auditors can validate")
    cur = db.cursor()
    cur.execute("SELECT assigned_auditor_id FROM reports WHERE id = ?", (report_id,))
    report = cur.fetchone()
    if not report or report['assigned_auditor_id'] != current_user['user_id']:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    cur.execute("UPDATE reports SET status = 'validated', auditor_feedback = ? WHERE id = ?", (req.feedback, report_id))
    return {"message": "Report validated successfully"}

@app.post("/reports/{report_id}/decision")
def admin_decision(report_id: int, req: DecisionRequest, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Only admin can make final decision")
        
    if req.decision not in ['approved', 'rejected', 'need more information']:
        raise HTTPException(status_code=400, detail="Invalid decision")
        
    cur = db.cursor()
    cur.execute("UPDATE reports SET status = ? WHERE id = ?", (req.decision, report_id))
    return {"message": f"Report marked as {req.decision}"}

@app.get("/users/profile")
def get_profile(db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    cur = db.cursor()
    cur.execute("SELECT profile_data_encrypted FROM users WHERE id = ?", (current_user['user_id'],))
    user = cur.fetchone()
    if not user or not user['profile_data_encrypted']:
        return {"profile_data": "N/A"}
        
    cur.execute("SELECT id FROM users WHERE role = 'admin'")
    admin = cur.fetchone()
    store = load_keystore()
    admin_keys = store.get(str(admin['id']))
        
    decrypted_profile = CustomECC.decrypt(json.loads(user['profile_data_encrypted']), admin_keys['ecc_priv'])
    return {"profile_data": decrypted_profile}

@app.put("/users/profile")
def update_profile(req: ProfileUpdateRequest, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user['role'] == 'admin':
        raise HTTPException(status_code=400, detail="Admin cannot update profile")
        
    cur = db.cursor()
    cur.execute("SELECT public_key_ecc FROM users WHERE role = 'admin'")
    admin_ecc_pub = json.loads(cur.fetchone()['public_key_ecc'])
    
    encrypted_profile = CustomECC.encrypt(req.profile_data, tuple(admin_ecc_pub))
    
    if req.new_email:
        uname_hash = CustomHash.hash(req.new_email)
        cur.execute("SELECT id FROM users WHERE username_hash = ? AND id != ?", (uname_hash, current_user['user_id']))
        if cur.fetchone():
             raise HTTPException(status_code=400, detail="Email already taken")
        cur.execute("UPDATE users SET profile_data_encrypted = ?, username_hash = ? WHERE id = ?", (json.dumps(encrypted_profile), uname_hash, current_user['user_id']))
    else:
        cur.execute("UPDATE users SET profile_data_encrypted = ? WHERE id = ?", (json.dumps(encrypted_profile), current_user['user_id']))
        
    return {"message": "Profile updated securely"}

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
