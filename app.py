import os
import time
import secrets
import shutil
import tempfile
import base64
import json
import urllib.request
import urllib.error
import hashlib
import hmac
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, File, UploadFile, BackgroundTasks, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.exceptions import HTTPException
from extractor import run_extraction

app = FastAPI(title="Bank Statement OCR Extractor")

# ── Auth config ────────────────────────────────────────────────────────────────
APP_USERNAME = os.environ.get("APP_USERNAME", "admin@vrtservices12.com")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "hon12345")
COOKIE_NAME  = "ocr_session"

# ── Dynamic CSV Export Layout Config ───────────────────────────────────────────
DEFAULT_CSV_MAPPING = {
    "headers": ["Type", "Date", "Entity Code", "Account", "Debit", "Credit", "Description", "Reference"],
    "fields": [
        {"header": "Type", "type": "constant", "value": "GJ"},
        {"header": "Date", "type": "field", "source": "date"},
        {"header": "Entity Code", "type": "constant", "value": ""},
        {"header": "Account", "type": "account_mapping", "debit_value": "260", "credit_value": "500"},
        {"header": "Debit", "type": "debit"},
        {"header": "Credit", "type": "credit"},
        {"header": "Description", "type": "field", "source": "description", "max_length": 98},
        {"header": "Reference", "type": "reference"}
    ]
}

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datalazo.config.json")
def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
    return {}

APP_CONFIG = load_config()

# Session tracking:
# valid_sessions: token -> {"username": str}
# active_user_tokens: username -> token (Enforces single active instance per user)
valid_sessions: dict[str, dict] = {}
active_user_tokens: dict[str, str] = {}

def create_user_session(username: str) -> str:
    """Creates a new session token, invalidating any previous session for the username."""
    username_clean = username.strip()
    old_token = active_user_tokens.get(username_clean)
    if old_token:
        valid_sessions.pop(old_token, None)

    token = secrets.token_urlsafe(32)
    valid_sessions[token] = {
        "username": username_clean
    }
    active_user_tokens[username_clean] = token
    return token

def get_current_session_info(request: Request) -> tuple[str | None, str | None, str | None]:
    """
    Validates cookie token. Checks:
    1. Token existence in valid_sessions
    2. Single active instance rule (active_user_tokens[username] == token)

    Returns (token, username, invalid_reason).
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None, None, None

    sess = valid_sessions.get(token)
    if not sess:
        return None, None, "Your account was logged in from another device or location."

    username = sess.get("username")

    # Single active instance check: Ensure token is still the active token for this username
    if active_user_tokens.get(username) != token:
        valid_sessions.pop(token, None)
        return None, None, "Your account was logged in from another device or location."

    return token, username, None

def get_current_session(request: Request) -> str | None:
    token, _, _ = get_current_session_info(request)
    return token

def get_current_username(request: Request) -> str | None:
    _, username, _ = get_current_session_info(request)
    return username

def require_auth(request: Request):
    """Redirect to login if not authenticated or not allowed on site."""
    username = get_current_username(request)
    if not username:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    allowed, _ = is_user_allowed_on_site(username, request)
    if not allowed:
        raise HTTPException(status_code=303, headers={"Location": "/login"})

# ── Site validation helpers ───────────────────────────────────────────────────
def get_request_host(request: Request) -> str:
    """Extract and normalize host domain from Request (handles X-Forwarded-Host and Host headers)."""
    forwarded = request.headers.get("x-forwarded-host")
    if forwarded:
        host = forwarded.split(",")[0].strip()
    else:
        host = request.headers.get("host", "")
    return host.split(":")[0].strip().lower()

def is_user_allowed_on_site(username: str, request: Request) -> tuple[bool, str]:
    """
    Checks if the given user is allowed to log in or access the application on the current request host.
    Returns (is_allowed: bool, assigned_subdomain: str).
    """
    request_host = get_request_host(request)

    # Allow local development/testing host names
    if request_host in ("localhost", "127.0.0.1", "testserver"):
        return True, ""

    # Allow default admin fallback user across domains
    if username == APP_USERNAME or username.lower() == "admin@vrtservices12.com":
        return True, ""

    assigned = get_user_assigned_subdomain(username)
    if not assigned:
        return True, ""

    assigned_subdomain = assigned.strip().lower()

    # Exact match (e.g. ocr.datalazo.net == ocr.datalazo.net)
    if request_host == assigned_subdomain:
        return True, assigned_subdomain

    # If assigned_subdomain is just the prefix (e.g. 'ocr')
    if "." not in assigned_subdomain:
        if request_host == assigned_subdomain or request_host.startswith(assigned_subdomain + "."):
            return True, assigned_subdomain

    # If request_host or assigned_subdomain are subdomains of each other
    if request_host.endswith("." + assigned_subdomain) or assigned_subdomain.endswith("." + request_host):
        return True, assigned_subdomain

    return False, assigned_subdomain

# ── Templates ──────────────────────────────────────────────────────────────────
templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
templates = Jinja2Templates(directory=templates_dir)

# ── Helpers ────────────────────────────────────────────────────────────────────
def cleanup_temp_dir(path: str):
    if os.path.exists(path):
        try:
            shutil.rmtree(path)
            print(f"Cleaned up temporary directory: {path}")
        except Exception as e:
            print(f"Failed to clean up temporary directory {path}: {e}")

# ── DB & Password helpers ──────────────────────────────────────────────────────
def get_db_connection():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        db_url = "postgresql://postgres:Paris2025%24@161.35.119.223:5432/datalazo?sslmode=disable"
    return psycopg2.connect(db_url)

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        parts = stored_hash.split(':')
        if len(parts) != 2:
            return False
        salt, key_hex = parts
        hashed_bytes = hashlib.scrypt(
            password.encode('utf-8'),
            salt=salt.encode('utf-8'),
            n=16384,
            r=8,
            p=1,
            dklen=64
        )
        key_bytes = bytes.fromhex(key_hex)
        return hmac.compare_digest(hashed_bytes, key_bytes)
    except Exception as e:
        print(f"Password verification error: {e}")
        return False

def get_client_user(username: str) -> dict | None:
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT * FROM "ClientUser" WHERE username = %s;', (username,))
            return cur.fetchone()
    except Exception as e:
        print(f"Database error fetching user: {e}")
        return None
    finally:
        if conn:
            conn.close()

def update_terms_accepted(username: str, ip: str, user_agent: str) -> bool:
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            import datetime
            now = datetime.datetime.now(datetime.timezone.utc)
            cur.execute(
                'UPDATE "ClientUser" SET "termsAccepted" = True, "termsAcceptedAt" = %s, "termsAcceptedIp" = %s, "termsAcceptedUserAgent" = %s WHERE username = %s;',
                (now, ip, user_agent, username)
            )
            conn.commit()
            return True
    except Exception as e:
        print(f"Database error updating terms: {e}")
        return False
    finally:
        if conn:
            conn.close()

def get_user_assigned_subdomain(username: str) -> str | None:
    user = get_client_user(username)
    if not user:
        return None
    
    client_id = user.get("clientId")
    if not client_id:
        return None
        
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT subdomain FROM "Client" WHERE id = %s;', (client_id,))
            client = cur.fetchone()
            if client and client.get("subdomain"):
                return client.get("subdomain").strip()
    except Exception as e:
        print(f"Database error fetching client subdomain: {e}")
    finally:
        if conn:
            conn.close()
            
    return None

def get_client_subdomain(username: str) -> str:
    subdomain = get_user_assigned_subdomain(username)
    return subdomain if subdomain else "vrt.datalazo.net"

def record_user_usage(username: str, page_count: int):
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT "monthlyUsageActual", "monthlyUsagePrevious", "updatedAt" FROM "ClientUser" WHERE username = %s;', (username,))
            user = cur.fetchone()
            if not user:
                return
            
            actual = user.get("monthlyUsageActual", 0) or 0
            prev = user.get("monthlyUsagePrevious", 0) or 0
            last_updated = user.get("updatedAt")
            
            import datetime
            now = datetime.datetime.now(datetime.timezone.utc)
            
            # Determine if a new month has started
            is_new_month = False
            if last_updated:
                # Remove timezone for database timestamps without time zone
                if last_updated.tzinfo is None:
                    now_compare = now.replace(tzinfo=None)
                else:
                    now_compare = now
                
                if (now_compare.year != last_updated.year) or (now_compare.month != last_updated.month):
                    is_new_month = True
            else:
                is_new_month = True
                
            if is_new_month:
                new_prev = actual
                new_actual = page_count
            else:
                new_prev = prev
                new_actual = actual + page_count
                
            cur.execute(
                'UPDATE "ClientUser" SET "monthlyUsageActual" = %s, "monthlyUsagePrevious" = %s, "updatedAt" = %s WHERE username = %s;',
                (new_actual, new_prev, now, username)
            )
            conn.commit()
            print(f"Recorded usage for {username}: {page_count} pages. Actual: {new_actual}, Previous: {new_prev}")
    except Exception as e:
        print(f"Database error recording usage: {e}")
    finally:
        if conn:
            conn.close()

def record_login(username: str, site: str, ip: str, user_agent: str):
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                'INSERT INTO "LoginLog" (username, site, "ipAddress", "userAgent") VALUES (%s, %s, %s, %s);',
                (username, site, ip, user_agent)
            )
            conn.commit()
            print(f"Recorded login log for {username} from {ip} on site {site}")
    except Exception as e:
        print(f"Database error recording login: {e}")
    finally:
        if conn:
            conn.close()

# ── Auth routes ────────────────────────────────────────────────────────────────
@app.get("/api/check-terms")
async def check_terms(username: str = ""):
    username_clean = username.strip()
    if not username_clean:
        return {"termsAccepted": False}
    user = get_client_user(username_clean)
    if user:
        return {"termsAccepted": bool(user.get("termsAccepted", False))}
    return {"termsAccepted": False}

@app.get("/api/session-status")
async def check_session_status(request: Request):
    token, username, reason = get_current_session_info(request)
    if not username:
        return {"valid": False, "reason": reason or "Session invalid."}
    allowed, assigned_site = is_user_allowed_on_site(username, request)
    if not allowed:
        return {"valid": False, "reason": f"Access denied: Your account is assigned to '{assigned_site}'."}
    return {"valid": True, "username": username}

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = "", username: str = ""):
    # Already logged in → check if allowed on current site
    current_username = get_current_username(request)
    if current_username:
        allowed, _ = is_user_allowed_on_site(current_username, request)
        if allowed:
            return RedirectResponse("/", status_code=302)
        else:
            token = request.cookies.get(COOKIE_NAME)
            if token:
                valid_sessions.pop(token, None)
    
    terms_accepted = False
    if username:
        user = get_client_user(username.strip())
        if user:
            terms_accepted = bool(user.get("termsAccepted", False))

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": error, "username": username, "terms_accepted": terms_accepted}
    )

@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    terms: str = Form(None)
):
    username_clean = username.strip()
    
    # 1. Try database client user authentication first
    user = get_client_user(username_clean)
    if user:
        if verify_password(password, user["password"]):
            # Validate site assignment permission
            allowed, assigned_site = is_user_allowed_on_site(username_clean, request)
            if not allowed:
                request_host = get_request_host(request)
                return templates.TemplateResponse(
                    request=request,
                    name="login.html",
                    context={
                        "error": f"Access denied: Your account is assigned to '{assigned_site}' and cannot log in on '{request_host}'.",
                        "username": username_clean,
                        "terms_accepted": bool(user.get("termsAccepted", False))
                    },
                    status_code=403
                )

            # Check terms and conditions acceptance status
            if not user.get("termsAccepted", False):
                if not terms:
                    return templates.TemplateResponse(
                        request=request,
                        name="login.html",
                        context={
                            "error": "You must accept the Terms and Conditions to proceed.",
                            "username": username_clean,
                            "terms_accepted": False
                        },
                        status_code=400
                    )
                else:
                    client_ip = request.client.host if request.client else "unknown"
                    user_agent = request.headers.get("user-agent", "")
                    update_terms_accepted(username_clean, client_ip, user_agent)
            
            # Create single active session and redirect
            token = create_user_session(username_clean)
            
            # Record login log
            client_ip = request.client.host if request.client else "unknown"
            user_agent = request.headers.get("user-agent", "")
            site_host = get_request_host(request)
            record_login(username_clean, site_host, client_ip, user_agent)
            
            response = RedirectResponse("/", status_code=302)
            response.set_cookie(
                key=COOKIE_NAME,
                value=token,
                httponly=True,
                samesite="lax",
                max_age=60 * 60 * 8,   # 8 hours
            )
            return response
            
    # 2. Fallback to default admin account
    if username_clean == APP_USERNAME and password == APP_PASSWORD:
        allowed, assigned_site = is_user_allowed_on_site(username_clean, request)
        if not allowed:
            request_host = get_request_host(request)
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={
                    "error": f"Access denied: Your account is assigned to '{assigned_site}' and cannot log in on '{request_host}'.",
                    "username": username_clean,
                    "terms_accepted": True
                },
                status_code=403
            )

        token = create_user_session(username_clean)
        
        # Record login log
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        site_host = get_request_host(request)
        record_login(username_clean, site_host, client_ip, user_agent)
        
        response = RedirectResponse("/", status_code=302)
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            httponly=True,
            samesite="lax",
            max_age=60 * 60 * 8,   # 8 hours
        )
        return response

    # Bad credentials
    terms_accepted = False
    if user:
        terms_accepted = bool(user.get("termsAccepted", False))

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": "Invalid email or password. Please try again.",
            "username": username_clean,
            "terms_accepted": terms_accepted
        },
        status_code=401,
    )

@app.get("/logout")
async def logout(request: Request, reason: str = ""):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        sess = valid_sessions.pop(token, None)
        if sess and isinstance(sess, dict) and "username" in sess:
            username = sess["username"]
            if active_user_tokens.get(username) == token:
                active_user_tokens.pop(username, None)
                
    redirect_url = "/login"
    if reason == "concurrent":
        redirect_url += "?error=Logged+out:+Your+account+was+accessed+from+another+device+or+location."

    response = RedirectResponse(redirect_url, status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response

# ── Protected routes ───────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    username = get_current_username(request)
    if not username:
        return RedirectResponse("/login", status_code=302)
        
    allowed, assigned_site = is_user_allowed_on_site(username, request)
    if not allowed:
        token = request.cookies.get(COOKIE_NAME)
        if token:
            valid_sessions.pop(token, None)
        request_host = get_request_host(request)
        response = RedirectResponse(
            f"/login?error=Access+denied:+Your+account+is+assigned+to+'{assigned_site}'.+You+cannot+access+'{request_host}'.",
            status_code=302
        )
        response.delete_cookie(COOKIE_NAME)
        return response

    company_name = None
    user = get_client_user(username)
    if user and user.get("clientId"):
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT company, name FROM "Client" WHERE id = %s;', (user["clientId"],))
                client = cur.fetchone()
                if client:
                    company_name = client.get("company") or client.get("name")
        except Exception as e:
            print(f"Error fetching client info: {e}")
        finally:
            if conn:
                conn.close()

    if not company_name:
        if username == APP_USERNAME or username.lower() == "admin@vrtservices12.com":
            company_name = "VRT Services"
        else:
            company_name = "Datalazo Partner"

    subdomain = get_client_subdomain(username)
    clients_config = APP_CONFIG.get("clients", {})
    client_conf = clients_config.get(subdomain) or clients_config.get("vrt.datalazo.net", {})
    
    if not client_conf or "csv_mapping" not in client_conf:
        client_conf = {"csv_mapping": DEFAULT_CSV_MAPPING}
        
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "client_config": client_conf,
            "username": username,
            "company_name": company_name or "Datalazo Partner"
        }
    )

@app.post("/process")
async def process_pdf(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    username = get_current_username(request)
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    allowed, assigned_site = is_user_allowed_on_site(username, request)
    if not allowed:
        raise HTTPException(status_code=403, detail=f"Access denied: Your account is assigned to '{assigned_site}'.")

    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")

    temp_dir = tempfile.mkdtemp()
    pdf_path = os.path.join(temp_dir, "input.pdf")
    try:
        with open(pdf_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        cleanup_temp_dir(temp_dir)
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")

    try:
        result_data = run_extraction(pdf_path, temp_dir, create_csv=False)
        
        # Record usage if logged in as a ClientUser
        current_username = get_current_username(request)
        if current_username:
            import fitz
            try:
                doc = fitz.open(pdf_path)
                page_count = len(doc)
                doc.close()
                record_user_usage(current_username, page_count)
            except Exception as ex:
                print(f"Error counting pages or recording usage: {ex}")
                
        background_tasks.add_task(cleanup_temp_dir, temp_dir)
        return result_data
    except ValueError as ve:
        cleanup_temp_dir(temp_dir)
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        cleanup_temp_dir(temp_dir)
        raise HTTPException(status_code=500, detail=f"Extraction failed: {str(e)}")

@app.post("/support")
async def support_submit(
    request: Request,
    message: str = Form(...),
    file: UploadFile = File(None)
):
    username = get_current_username(request)
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    allowed, assigned_site = is_user_allowed_on_site(username, request)
    if not allowed:
        raise HTTPException(status_code=403, detail=f"Access denied: Your account is assigned to '{assigned_site}'.")

    resend_key = (
        os.environ.get("RESEND_API_KEY") or
        os.environ.get("RESEND_KEY") or
        os.environ.get("RESEND_API_TOKEN") or
        os.environ.get("RESEND_TOKEN")
    )
    if resend_key:
        resend_key = resend_key.strip().strip('\'"')
    if not resend_key or not resend_key.startswith("re_"):
        raise HTTPException(
            status_code=500,
            detail="Support email feature is not configured: Resend API Key is missing or invalid on the server. Please add your Resend API Key (e.g., RESEND_API_KEY) in Easypanel environment variables."
        )

    from_email = (
        os.environ.get("RESEND_FROM_EMAIL") or
        os.environ.get("FROM_EMAIL") or
        os.environ.get("SENDER_EMAIL")
    )
    if from_email:
        from_email = from_email.strip().strip('\'"')
    if not from_email or "@" not in from_email:
        from_email = "support@datalazo.net"
        
    to_email = (
        os.environ.get("RESEND_TO_EMAIL") or
        os.environ.get("TO_EMAIL") or
        os.environ.get("SUPPORT_EMAIL")
    )
    if to_email:
        to_email = to_email.strip().strip('\'"')
    if not to_email or "@" not in to_email:
        to_email = "luislazo@datalazo.net"
    
    subject = "Support Request - Bank Statement OCR Extractor"
    
    current_user = get_current_username(request) or APP_USERNAME
    html_content = f"""
    <h3>Support Request</h3>
    <p><strong>User:</strong> {current_user}</p>
    <p><strong>Message:</strong></p>
    <p>{message.replace(chr(10), '<br>')}</p>
    """
    
    attachments = []
    if file and file.filename:
        file_bytes = await file.read()
        if len(file_bytes) > 0:
            b64_content = base64.b64encode(file_bytes).decode('utf-8')
            attachments.append({
                "filename": file.filename,
                "content": b64_content
            })
            
    payload = {
        "from": from_email,
        "to": [to_email],
        "subject": subject,
        "html": html_content
    }
    if attachments:
        payload["attachments"] = attachments
        
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode('utf-8'),
        headers={
            "Authorization": f"Bearer {resend_key}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        },
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            res_body = response.read().decode('utf-8')
            print(f"Resend email sent successfully: {res_body}")
            return {"status": "success", "message": "Support email sent successfully."}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8')
        print(f"Failed to send email via Resend: Code {e.code}, Response: {err_body}")
        
        found_key = resend_key or ""
        masked_env = f"{found_key[:6]}...{found_key[-4:]}" if len(found_key) > 10 else found_key
        raise HTTPException(status_code=500, detail=f"Failed to send support email: {err_body}. Used Key: {masked_env}, From: {from_email}")
    except Exception as e:
        print(f"Error occurred while sending email: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error sending email: {str(e)}")

# ── Health / debug ─────────────────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    import json as _json
    
    # 1. Check Google Vision credentials
    google_status = "error"
    google_detail = "MISSING"
    google_error = None
    
    # Check GOOGLE_CREDENTIALS_JSON env var
    creds_raw = os.environ.get("GOOGLE_CREDENTIALS_JSON", "")
    if creds_raw:
        creds_stripped = creds_raw.strip().strip('"\'')
        try:
            info = _json.loads(creds_stripped)
            google_status = "ok"
            google_detail = f"GOOGLE_CREDENTIALS_JSON: OK — project_id={info.get('project_id')}, client_email={info.get('client_email')}"
        except Exception as e:
            google_detail = "GOOGLE_CREDENTIALS_JSON: INVALID JSON"
            google_error = str(e)
            
    # Check GOOGLE_APPLICATION_CREDENTIALS file path
    if google_status != "ok":
        env_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if env_path:
            env_path_stripped = env_path.strip().strip('"\'')
            if os.path.exists(env_path_stripped):
                google_status = "ok"
                google_detail = f"GOOGLE_APPLICATION_CREDENTIALS file exists: {env_path_stripped}"
            else:
                google_detail = f"GOOGLE_APPLICATION_CREDENTIALS path specified but file not found: {env_path_stripped}"
                
    # Check Fallback paths
    if google_status != "ok":
        fallback_paths = [
            r"C:\keys\vision-keyvtr.json",
            r"/keys/vision-keyvtr.json",
            r"C:\keys\vision-key.json",
            r"/keys/vision-key.json",
        ]
        for path in fallback_paths:
            if os.path.exists(path):
                google_status = "ok"
                google_detail = f"Fallback file exists: {path}"
                break

    # 2. Check Support Email (Resend) credentials
    resend_key = (
        os.environ.get("RESEND_API_KEY") or
        os.environ.get("RESEND_KEY") or
        os.environ.get("RESEND_API_TOKEN") or
        os.environ.get("RESEND_TOKEN")
    )
    
    resend_status = "error"
    resend_detail = "MISSING"
    
    if resend_key:
        resend_key = resend_key.strip().strip('\'"')
        if resend_key.startswith("re_"):
            resend_status = "ok"
            masked_key = f"{resend_key[:6]}...{resend_key[-4:]}" if len(resend_key) > 10 else "re_..."
            resend_detail = f"Configured (API Key: {masked_key})"
        else:
            resend_detail = "Invalid API Key format (Must start with 're_')"
            
    from_email = (
        os.environ.get("RESEND_FROM_EMAIL") or
        os.environ.get("FROM_EMAIL") or
        os.environ.get("SENDER_EMAIL") or
        "support@datalazo.net"
    )
    if from_email:
        from_email = from_email.strip().strip('\'"')
        
    to_email = (
        os.environ.get("RESEND_TO_EMAIL") or
        os.environ.get("TO_EMAIL") or
        os.environ.get("SUPPORT_EMAIL") or
        "luislazo@datalazo.net"
    )
    if to_email:
        to_email = to_email.strip().strip('\'"')

    # Overall health check status (depends primarily on extraction pipeline's Google Vision capability)
    overall_status = "ok" if google_status == "ok" else "error"
    
    return {
        "status": overall_status,
        "google_vision": {
            "status": google_status,
            "detail": google_detail,
            "error": google_error
        },
        "support_email": {
            "status": resend_status,
            "detail": resend_detail,
            "from_email": from_email,
            "to_email": to_email
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

