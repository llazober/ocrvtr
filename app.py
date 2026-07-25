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

    # Persist session token in database so server redeployments/restarts keep users logged in
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                'UPDATE "ClientUser" SET "sessionToken" = %s WHERE username = %s;',
                (token, username_clean)
            )
            conn.commit()
    except Exception as e:
        print(f"Database error updating sessionToken: {e}")
    finally:
        if conn:
            conn.close()

    return token

def get_current_session_info(request: Request) -> tuple[str | None, str | None, str | None]:
    """
    Validates cookie token. Checks:
    1. Token existence in valid_sessions
    2. Single active instance rule (active_user_tokens[username] == token)
    3. Database fallback lookup across server restarts

    Returns (token, username, invalid_reason).
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None, None, None

    sess = valid_sessions.get(token)
    if sess:
        username = sess.get("username")
        if active_user_tokens.get(username) == token:
            return token, username, None

    # Fallback lookup in DB if server was restarted and in-memory dicts were reset
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT username FROM "ClientUser" WHERE "sessionToken" = %s;', (token,))
            user = cur.fetchone()
            if user and user.get("username"):
                username_clean = user.get("username")
                valid_sessions[token] = {"username": username_clean}
                active_user_tokens[username_clean] = token
                return token, username_clean, None
    except Exception as e:
        pass
    finally:
        if conn:
            conn.close()

    return None, None, "Your account was logged in from another device or location."

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

def is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    clean_ip = ip.strip().replace("::ffff:", "")
    if clean_ip in ("127.0.0.1", "::1", "localhost"):
        return True
    parts = clean_ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        p0, p1 = int(parts[0]), int(parts[1])
        if p0 == 10:
            return True
        if p0 == 172 and 16 <= p1 <= 31:
            return True
        if p0 == 192 and p1 == 168:
            return True
        if p0 == 169 and p1 == 254:
            return True
        if p0 == 127:
            return True
    return False

def get_real_client_ip(request: Request) -> str:
    """Extract real client IP address, handling Cloudflare, proxies, and filtering private IPs (like 10.1.0.10)."""
    candidates = []

    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        candidates.append(cf_ip)

    true_client_ip = request.headers.get("true-client-ip")
    if true_client_ip:
        candidates.append(true_client_ip)

    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        candidates.append(x_real_ip)

    x_client_ip = request.headers.get("x-client-ip")
    if x_client_ip:
        candidates.append(x_client_ip)

    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        for ip in x_forwarded_for.split(","):
            candidates.append(ip.strip())

    if request.client and request.client.host:
        candidates.append(request.client.host)

    for raw_ip in candidates:
        clean = raw_ip.strip().replace("::ffff:", "")
        if clean and not is_private_ip(clean):
            return clean

    for raw_ip in candidates:
        clean = raw_ip.strip().replace("::ffff:", "")
        if clean:
            return clean

    return "127.0.0.1"

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

def get_client_coa(client_name: str) -> list[dict]:
    """Fetch Chart of Accounts list for a client from ClientChartOfAccounts table."""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('''
                SELECT "accountNumber", "accountName", "type", "subType", "level"
                FROM "ClientChartOfAccounts"
                WHERE LOWER("clientName") = LOWER(%s) OR "clientName" = 'DEFAULT'
                ORDER BY "accountNumber" ASC;
            ''', (client_name,))
            return cur.fetchall() or []
    except Exception as e:
        print(f"Database error fetching COA for {client_name}: {e}")
        return []
    finally:
        if conn:
            conn.close()

def get_client_history_rules(client_name: str) -> list[dict]:
    """Fetch learned vendor matching rules from ClientTransactionHistory table with fallbacks."""
    conn = None
    rules = []
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if client_name:
                cur.execute('''
                    SELECT "pattern", "accountNumber", "accountName", "transactionType", "useCount"
                    FROM "ClientTransactionHistory"
                    WHERE LOWER("clientName") = LOWER(%s) OR "clientName" = 'DEFAULT'
                    ORDER BY "useCount" DESC;
                ''', (client_name,))
                rules = cur.fetchall() or []
            
            if not rules:
                cur.execute('''
                    SELECT "pattern", "accountNumber", "accountName", "transactionType", "useCount"
                    FROM "ClientTransactionHistory"
                    ORDER BY "useCount" DESC;
                ''')
                rules = cur.fetchall() or []
    except Exception as e:
        print(f"Database error fetching history rules for {client_name}: {e}")
    finally:
        if conn:
            conn.close()

    if not rules:
        try:
            json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "toirak_mapped_rules.json")
            if os.path.exists(json_path):
                with open(json_path, "r", encoding="utf-8") as f:
                    rules = json.load(f)
                print(f"--> Loaded {len(rules)} fallback rules from toirak_mapped_rules.json")
        except Exception as ex:
            print(f"Error loading toirak_mapped_rules.json: {ex}")

    return rules

def save_history_rule(client_name: str, pattern: str, account_number: str, account_name: str = "", tx_type: str = "ALL") -> bool:
    """Save or update a learned vendor rule in ClientTransactionHistory table."""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute('''
                INSERT INTO "ClientTransactionHistory" ("clientName", "pattern", "accountNumber", "accountName", "transactionType", "source", "useCount")
                VALUES (%s, %s, %s, %s, %s, 'USER_EDIT', 1)
                ON CONFLICT ("clientName", "pattern", "transactionType")
                DO UPDATE SET
                    "accountNumber" = EXCLUDED."accountNumber",
                    "accountName" = EXCLUDED."accountName",
                    "useCount" = "ClientTransactionHistory"."useCount" + 1,
                    "updatedAt" = CURRENT_TIMESTAMP;
            ''', (client_name, pattern.upper().strip(), account_number.strip(), account_name.strip(), tx_type))
            conn.commit()
            return True
    except Exception as e:
        print(f"Database error saving history rule: {e}")
        return False
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

# ── QuickBooks Online (QBO) OAuth & API Integration ───────────────────────────
QBO_CLIENT_ID     = os.environ.get("QBO_CLIENT_ID", "")
QBO_CLIENT_SECRET = os.environ.get("QBO_CLIENT_SECRET", "")
QBO_REDIRECT_URI  = os.environ.get("QBO_REDIRECT_URI", "https://datalazo.net/auth/qbo/callback")
QBO_ENVIRONMENT   = os.environ.get("QBO_ENVIRONMENT", "sandbox").lower()

QBO_AUTH_URL      = "https://appcenter.intuit.com/connect/oauth2"
QBO_TOKEN_URL     = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"

def get_qbo_api_base_url(realm_id: str) -> str:
    if QBO_ENVIRONMENT == "production":
        return f"https://quickbooks.api.intuit.com/v3/company/{realm_id}"
    else:
        return f"https://sandbox-quickbooks.api.intuit.com/v3/company/{realm_id}"

def init_qbo_db():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS "QboConnection" (
                    "id" SERIAL PRIMARY KEY,
                    "clientId" TEXT UNIQUE NOT NULL,
                    "realmId" TEXT NOT NULL,
                    "accessToken" TEXT NOT NULL,
                    "refreshToken" TEXT NOT NULL,
                    "accessTokenExpiresAt" TIMESTAMP WITH TIME ZONE,
                    "refreshTokenExpiresAt" TIMESTAMP WITH TIME ZONE,
                    "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            try:
                cur.execute('ALTER TABLE "ClientUser" ADD COLUMN IF NOT EXISTS "sessionToken" TEXT;')
            except Exception as e_col:
                print(f"sessionToken column check: {e_col}")
            conn.commit()
    except Exception as e:
        print(f"Error initializing QboConnection table: {e}")
    finally:
        if conn:
            conn.close()

init_qbo_db()

def save_qbo_connection(client_id_key: str, realm_id: str, access_token: str, refresh_token: str, expires_in: int, refresh_expires_in: int = 8726400):
    conn = None
    try:
        conn = get_db_connection()
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        access_expires_at = now + datetime.timedelta(seconds=expires_in)
        refresh_expires_at = now + datetime.timedelta(seconds=refresh_expires_in)
        
        with conn.cursor() as cur:
            cur.execute('''
                INSERT INTO "QboConnection" ("clientId", "realmId", "accessToken", "refreshToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "updatedAt")
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT ("clientId") DO UPDATE SET
                    "realmId" = EXCLUDED."realmId",
                    "accessToken" = EXCLUDED."accessToken",
                    "refreshToken" = EXCLUDED."refreshToken",
                    "accessTokenExpiresAt" = EXCLUDED."accessTokenExpiresAt",
                    "refreshTokenExpiresAt" = EXCLUDED."refreshTokenExpiresAt",
                    "updatedAt" = EXCLUDED."updatedAt";
            ''', (client_id_key, realm_id, access_token, refresh_token, access_expires_at, refresh_expires_at, now))
            conn.commit()
            return True
    except Exception as e:
        print(f"Error saving QboConnection: {e}")
        return False
    finally:
        if conn:
            conn.close()

def get_qbo_connection(client_id_key: str) -> dict | None:
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute('SELECT * FROM "QboConnection" WHERE "clientId" = %s;', (client_id_key,))
            return cur.fetchone()
    except Exception as e:
        print(f"Error fetching QboConnection: {e}")
        return None
    finally:
        if conn:
            conn.close()

def refresh_qbo_tokens(refresh_token: str) -> dict | None:
    if not QBO_CLIENT_ID or not QBO_CLIENT_SECRET:
        return None

    import urllib.parse
    auth_header = base64.b64encode(f"{QBO_CLIENT_ID}:{QBO_CLIENT_SECRET}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    body = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }).encode("utf-8")

    req = urllib.request.Request(QBO_TOKEN_URL, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data
    except Exception as e:
        print(f"Error refreshing QBO token: {e}")
        return None

def get_valid_qbo_access_token(client_id_key: str) -> tuple[str | None, str | None]:
    qbo_conn = get_qbo_connection(client_id_key)
    if not qbo_conn:
        return None, None

    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    access_expires_at = qbo_conn.get("accessTokenExpiresAt")
    
    if access_expires_at:
        if access_expires_at.tzinfo is None:
            now_compare = now.replace(tzinfo=None)
        else:
            now_compare = now
            
        if access_expires_at <= (now_compare + datetime.timedelta(minutes=5)):
            res = refresh_qbo_tokens(qbo_conn["refreshToken"])
            if res and "access_token" in res:
                new_access_token = res["access_token"]
                new_refresh_token = res.get("refresh_token", qbo_conn["refreshToken"])
                expires_in = res.get("expires_in", 3600)
                refresh_expires_in = res.get("x_refresh_token_expires_in", 8726400)
                save_qbo_connection(client_id_key, qbo_conn["realmId"], new_access_token, new_refresh_token, expires_in, refresh_expires_in)
                return new_access_token, qbo_conn["realmId"]
            else:
                return None, None

    return qbo_conn["accessToken"], qbo_conn["realmId"]

def fetch_qbo_chart_of_accounts(access_token: str, realm_id: str) -> list[dict]:
    import urllib.parse
    base_url = get_qbo_api_base_url(realm_id)
    query = "SELECT * FROM Account MAXRESULTS 1000"
    url = f"{base_url}/query?query={urllib.parse.quote(query)}&minorversion=65"
    
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    })
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            query_response = data.get("QueryResponse", {})
            return query_response.get("Account", [])
    except Exception as e:
        print(f"Error fetching QBO Chart of Accounts: {e}")
        return []

def resolve_qbo_account_ids(access_token: str, realm_id: str, debit_num="260", credit_num="500") -> tuple[dict | None, dict | None]:
    accounts = fetch_qbo_chart_of_accounts(access_token, realm_id)
    
    debit_acc = None
    credit_acc = None
    
    for acc in accounts:
        acct_num = str(acc.get("AcctNum", "")).strip()
        name = str(acc.get("Name", "")).strip()
        
        if not debit_acc and (acct_num == str(debit_num) or name == str(debit_num)):
            debit_acc = acc
        if not credit_acc and (acct_num == str(credit_num) or name == str(credit_num)):
            credit_acc = acc
            
    if not debit_acc:
        for acc in accounts:
            if acc.get("AccountType") in ("Bank", "Other Current Asset"):
                debit_acc = acc
                break
    if not credit_acc:
        for acc in accounts:
            if acc.get("AccountType") in ("Expense", "Cost of Goods Sold", "Other Expense"):
                credit_acc = acc
                break

    if not debit_acc and accounts:
        debit_acc = accounts[0]
    if not credit_acc and len(accounts) > 1:
        credit_acc = accounts[1]
    elif not credit_acc and accounts:
        credit_acc = accounts[0]

    return debit_acc, credit_acc

def fetch_qbo_company_name(access_token: str, realm_id: str) -> str:
    base_url = get_qbo_api_base_url(realm_id)
    url = f"{base_url}/companyinfo/{realm_id}?minorversion=65"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    })
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            cinfo = data.get("CompanyInfo", {})
            return cinfo.get("CompanyName", "") or ""
    except Exception as e:
        print(f"Error fetching QBO company name: {e}")
        return ""


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
                    client_ip = get_real_client_ip(request)
                    user_agent = request.headers.get("user-agent", "")
                    update_terms_accepted(username_clean, client_ip, user_agent)
            
            # Create single active session and redirect
            token = create_user_session(username_clean)
            
            # Record login log
            client_ip = get_real_client_ip(request)
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
        client_ip = get_real_client_ip(request)
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
async def read_index(request: Request, msg: str = "", error: str = ""):
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
    software_name = None
    user = get_client_user(username)
    client_id_key = str(user.get("clientId")) if (user and user.get("clientId")) else username

    if user and user.get("clientId"):
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                try:
                    cur.execute('SELECT company, name, "software" FROM "Client" WHERE id = %s;', (user["clientId"],))
                    client = cur.fetchone()
                    if client:
                        company_name = client.get("company") or client.get("name")
                        software_name = client.get("software") or client.get("Software")
                except Exception as e_col:
                    conn.rollback()
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
    software_config = APP_CONFIG.get("software", {})
    clients_config = APP_CONFIG.get("clients", {})

    client_conf = None
    if software_name and isinstance(software_name, str):
        clean_software = software_name.strip()
        client_conf = software_config.get(clean_software)
        if not client_conf:
            for key, val in software_config.items():
                if key.lower() == clean_software.lower():
                    client_conf = val
                    break

    if not client_conf:
        client_conf = clients_config.get(subdomain) or software_config.get("Default") or clients_config.get("vrt.datalazo.net", {})

    if not client_conf or "csv_mapping" not in client_conf:
        client_conf = {"csv_mapping": DEFAULT_CSV_MAPPING}

    # Check QBO connection status
    qbo_token, qbo_realm_id = get_valid_qbo_access_token(client_id_key)
    qbo_connected = bool(qbo_token and qbo_realm_id)
    qbo_company_name = ""
    if qbo_connected:
        qbo_company_name = fetch_qbo_company_name(qbo_token, qbo_realm_id)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "client_config": client_conf,
            "username": username,
            "company_name": company_name or "Datalazo Partner",
            "software_name": software_name or "",
            "qbo_connected": qbo_connected,
            "qbo_realm_id": qbo_realm_id or "",
            "qbo_company_name": qbo_company_name or "",
            "msg": msg,
            "error": error
        }
    )

# ── QBO OAuth & Export API Routes ──────────────────────────────────────────────
@app.get("/auth/qbo/login")
async def qbo_login(request: Request):
    username = get_current_username(request)
    if not username:
        return RedirectResponse("/login", status_code=302)

    if not QBO_CLIENT_ID or not QBO_CLIENT_SECRET:
        return RedirectResponse("/?error=QuickBooks+API+credentials+not+configured+on+server", status_code=302)

    user = get_client_user(username)
    client_id_key = str(user.get("clientId")) if (user and user.get("clientId")) else username
    origin_host = get_request_host(request)

    import urllib.parse
    state_token = secrets.token_urlsafe(16)
    state_val = f"{origin_host}|{client_id_key}|{state_token}"
    params = {
        "client_id": QBO_CLIENT_ID,
        "response_type": "code",
        "scope": "com.intuit.quickbooks.accounting",
        "redirect_uri": QBO_REDIRECT_URI,
        "state": state_val
    }
    auth_redirect = f"{QBO_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(auth_redirect, status_code=302)

@app.get("/auth/qbo/callback")
async def qbo_callback(request: Request, code: str = "", state: str = "", realmId: str = "", error: str = ""):
    parts = state.split("|") if "|" in state else [state]
    origin_host = parts[0] if len(parts) >= 2 else ""
    client_id_key = parts[1] if len(parts) >= 2 else parts[0]

    scheme = "http" if origin_host in ("localhost", "127.0.0.1", "testserver") else "https"
    redirect_prefix = f"{scheme}://{origin_host}" if origin_host else ""

    if error:
        return RedirectResponse(f"{redirect_prefix}/?error=QuickBooks+Auth+Error:+{error}", status_code=302)

    if not code or not realmId:
        return RedirectResponse(f"{redirect_prefix}/?error=QuickBooks+connection+failed:+Missing+code+or+realmId", status_code=302)

    import urllib.parse
    auth_header = base64.b64encode(f"{QBO_CLIENT_ID}:{QBO_CLIENT_SECRET}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": QBO_REDIRECT_URI
    }).encode("utf-8")

    req = urllib.request.Request(QBO_TOKEN_URL, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))
            access_token = token_data.get("access_token")
            refresh_token = token_data.get("refresh_token")
            expires_in = token_data.get("expires_in", 3600)
            refresh_expires_in = token_data.get("x_refresh_token_expires_in", 8726400)

            if access_token and refresh_token:
                save_qbo_connection(client_id_key, realmId, access_token, refresh_token, expires_in, refresh_expires_in)
                return RedirectResponse(f"{redirect_prefix}/?msg=QuickBooks+Online+Connected+Successfully!", status_code=302)
    except Exception as e:
        print(f"Error exchanging QBO authorization code: {e}")

    return RedirectResponse(f"{redirect_prefix}/?error=Failed+to+exchange+QuickBooks+token", status_code=302)

@app.get("/api/qbo/status")
async def qbo_status(request: Request):
    username = get_current_username(request)
    if not username:
        return {"connected": False}
    user = get_client_user(username)
    client_id_key = str(user.get("clientId")) if (user and user.get("clientId")) else username
    access_token, realm_id = get_valid_qbo_access_token(client_id_key)
    return {"connected": bool(access_token and realm_id), "realm_id": realm_id or ""}

def parse_to_qbo_date(date_str: str) -> str:
    import datetime, re
    if not date_str:
        return datetime.date.today().strftime("%Y-%m-%d")
    date_str = str(date_str).strip()
    
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y", "%d/%m/%Y", "%d/%m/%y", "%b %d, %Y", "%B %d, %Y"):
        try:
            dt = datetime.datetime.strptime(date_str, fmt)
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            pass
            
    match = re.search(r'(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})', date_str)
    if match:
        m, d, y = match.groups()
        if len(y) == 2:
            y = "20" + y
        return f"{int(y):04d}-{int(m):02d}-{int(d):02d}"

    return datetime.date.today().strftime("%Y-%m-%d")

@app.post("/api/qbo/export")
async def export_to_qbo(request: Request):
    username = get_current_username(request)
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    user = get_client_user(username)
    client_id_key = str(user.get("clientId")) if (user and user.get("clientId")) else username

    access_token, realm_id = get_valid_qbo_access_token(client_id_key)
    if not access_token or not realm_id:
        raise HTTPException(status_code=400, detail="QuickBooks is not connected. Please connect QuickBooks first.")

    payload = await request.json()
    transactions = payload.get("transactions", [])
    batch_mode = payload.get("batch_mode", True)

    if not transactions:
        raise HTTPException(status_code=400, detail="No transactions provided to sync.")

    business_name = payload.get("business_name") or ""
    credit_account_code = "656" if "payano" in str(business_name).lower() else "500"

    # Dynamically resolve Chart of Accounts for 260 and 500/656
    debit_acc, credit_acc = resolve_qbo_account_ids(access_token, realm_id, "260", credit_account_code)
    if not debit_acc or not credit_acc:
        raise HTTPException(status_code=400, detail="Could not resolve Chart of Accounts in QuickBooks Online.")

    # Group transactions: Batch mode (1 entry for all) vs Per Date mode (1 entry per date)
    tx_by_date = {}
    if batch_mode:
        latest_date = parse_to_qbo_date(transactions[-1].get("date") if transactions else None)
        tx_by_date[latest_date] = transactions
    else:
        for tx in transactions:
            qbo_date = parse_to_qbo_date(tx.get("date"))
            if qbo_date not in tx_by_date:
                tx_by_date[qbo_date] = []
            tx_by_date[qbo_date].append(tx)

    created_ids = []
    base_url = get_qbo_api_base_url(realm_id)
    post_url = f"{base_url}/journalentry?minorversion=65"

    for qbo_date, tx_list in tx_by_date.items():
        lines = []
        for tx in tx_list:
            dep = tx.get("Deposits")
            withd = tx.get("Withdrawals")
            desc = tx.get("description", "Bank Statement Transaction")
            if not desc:
                desc = "Bank Statement Transaction"
            desc = str(desc)[:100]

            has_debit = dep is not None and dep != ""
            has_credit = withd is not None and withd != ""

            if has_debit:
                amt = float(dep)
                lines.append({
                    "Description": desc,
                    "Amount": amt,
                    "DetailType": "JournalEntryLineDetail",
                    "JournalEntryLineDetail": {
                        "PostingType": "Debit",
                        "AccountRef": {
                            "value": str(debit_acc["Id"]),
                            "name": str(debit_acc.get("Name", "Debit Account"))
                        }
                    }
                })
                lines.append({
                    "Description": desc,
                    "Amount": amt,
                    "DetailType": "JournalEntryLineDetail",
                    "JournalEntryLineDetail": {
                        "PostingType": "Credit",
                        "AccountRef": {
                            "value": str(credit_acc["Id"]),
                            "name": str(credit_acc.get("Name", "Credit Account"))
                        }
                    }
                })
            elif has_credit:
                amt = float(withd)
                lines.append({
                    "Description": desc,
                    "Amount": amt,
                    "DetailType": "JournalEntryLineDetail",
                    "JournalEntryLineDetail": {
                        "PostingType": "Credit",
                        "AccountRef": {
                            "value": str(debit_acc["Id"]),
                            "name": str(debit_acc.get("Name", "Debit Account"))
                        }
                    }
                })
                lines.append({
                    "Description": desc,
                    "Amount": amt,
                    "DetailType": "JournalEntryLineDetail",
                    "JournalEntryLineDetail": {
                        "PostingType": "Debit",
                        "AccountRef": {
                            "value": str(credit_acc["Id"]),
                            "name": str(credit_acc.get("Name", "Credit Account"))
                        }
                    }
                })

        if not lines:
            continue

        qbo_payload = {
            "TxnDate": qbo_date,
            "Line": lines
        }

        req = urllib.request.Request(
            post_url,
            data=json.dumps(qbo_payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                je = resp_data.get("JournalEntry", {})
                je_id = je.get("Id")
                if je_id:
                    created_ids.append(str(je_id))
        except urllib.error.HTTPError as he:
            err_body = he.read().decode("utf-8")
            print(f"QBO API Error: {err_body}")
            raise HTTPException(status_code=400, detail=f"QuickBooks API Error: {err_body}")
        except Exception as e:
            print(f"Error posting to QBO: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to post to QuickBooks Online: {e}")

    if not created_ids:
        raise HTTPException(status_code=400, detail="No valid Journal Entries could be created in QuickBooks.")

    if len(created_ids) == 1:
        msg_text = f"Successfully created Batch Journal Entry #{created_ids[0]} in QuickBooks Online!"
    else:
        id_str = ", #".join(created_ids)
        msg_text = f"Successfully created Journal Entries #{id_str} in QuickBooks Online!"

    return {
        "success": True,
        "journal_entry_ids": created_ids,
        "message": msg_text,
        "debit_account": debit_acc.get("Name"),
        "credit_account": credit_acc.get("Name")
    }

@app.get("/api/coa")
async def get_coa_endpoint(request: Request, client_name: str = "Toirak's Group Homes Inc"):
    username = get_current_username(request)
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    coa_list = get_client_coa(client_name)
    return {"success": True, "client_name": client_name, "coa": coa_list}

@app.post("/api/history/learn")
async def learn_history_rule_endpoint(request: Request):
    username = get_current_username(request)
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    payload = await request.json()
    client_name = payload.get("client_name") or "DEFAULT"
    pattern = payload.get("pattern") or ""
    account_number = payload.get("account_number") or ""
    account_name = payload.get("account_name") or ""
    tx_type = payload.get("transaction_type") or "ALL"
    
    if not pattern or not account_number:
        raise HTTPException(status_code=400, detail="Pattern and account_number are required.")
        
    ok = save_history_rule(client_name, pattern, account_number, account_name, tx_type)
    return {"success": ok, "message": f"Rule learned for '{pattern}' -> {account_number}"}

@app.post("/process")
async def process_pdf(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    use_history: bool = Form(False),
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
        result_data = run_extraction(
            pdf_path, 
            temp_dir, 
            create_csv=False, 
            use_history=use_history, 
            client_history_fetcher=get_client_history_rules
        )
        
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

