import os
import secrets
import shutil
import tempfile
import base64
import json
import urllib.request
import urllib.error
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

# In-memory set of valid session tokens (cleared on restart — fine for single user)
valid_sessions: set[str] = set()

def get_current_session(request: Request) -> str | None:
    token = request.cookies.get(COOKIE_NAME)
    return token if token in valid_sessions else None

def require_auth(request: Request):
    """Redirect to login if not authenticated."""
    if not get_current_session(request):
        raise HTTPException(status_code=303, headers={"Location": "/login"})

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

# ── Auth routes ────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    # Already logged in → go home
    if get_current_session(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request=request, name="login.html", context={"error": error})

@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if username.strip() == APP_USERNAME and password == APP_PASSWORD:
        token = secrets.token_urlsafe(32)
        valid_sessions.add(token)
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
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": "Invalid email or password. Please try again."},
        status_code=401,
    )

@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        valid_sessions.discard(token)
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response

# ── Protected routes ───────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    if not get_current_session(request):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/process")
async def process_pdf(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    if not get_current_session(request):
        raise HTTPException(status_code=401, detail="Not authenticated.")

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
        background_tasks.add_task(cleanup_temp_dir, temp_dir)
        return result_data
    except Exception as e:
        cleanup_temp_dir(temp_dir)
        raise HTTPException(status_code=500, detail=f"Extraction failed: {str(e)}")

@app.post("/support")
async def support_submit(
    request: Request,
    message: str = Form(...),
    file: UploadFile = File(None)
):
    if not get_current_session(request):
        raise HTTPException(status_code=401, detail="Not authenticated.")

    resend_key = os.environ.get("RESEND_API_KEY")
    if not resend_key or not resend_key.strip() or not resend_key.startswith("re_"):
        resend_key = "re_LUvcnmLD_AMMTLePHQzmBFn9gV1wKCqra"
    from_email = os.environ.get("RESEND_FROM_EMAIL")
    if not from_email or not from_email.strip() or "@" not in from_email:
        from_email = "vrt@nelsonmar.com"
    to_email = "luislazo@datalazo.net"
    
    subject = "Support Request - Bank Statement OCR Extractor"
    
    html_content = f"""
    <h3>Support Request</h3>
    <p><strong>User:</strong> {APP_USERNAME}</p>
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
        raise HTTPException(status_code=500, detail=f"Failed to send support email: {err_body}")
    except Exception as e:
        print(f"Error occurred while sending email: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error sending email: {str(e)}")

# ── Health / debug ─────────────────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    import json as _json
    status = {"status": "ok", "credentials": None, "error": None}
    
    # 1. Check GOOGLE_CREDENTIALS_JSON
    creds_raw = os.environ.get("GOOGLE_CREDENTIALS_JSON", "")
    if creds_raw:
        creds_stripped = creds_raw.strip().strip('"\'')
        try:
            info = _json.loads(creds_stripped)
            status["credentials"] = f"GOOGLE_CREDENTIALS_JSON: OK — project_id={info.get('project_id')}, client_email={info.get('client_email')}"
            return status
        except Exception as e:
            status["credentials"] = "GOOGLE_CREDENTIALS_JSON: INVALID JSON"
            status["error"] = str(e)
            status["status"] = "error"
            
    # 2. Check GOOGLE_APPLICATION_CREDENTIALS file
    env_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if env_path and os.path.exists(env_path):
        status["status"] = "ok"
        status["credentials"] = f"GOOGLE_APPLICATION_CREDENTIALS file exists: {env_path}"
        status["error"] = None
        return status

    # 3. Check Fallbacks
    fallback_paths = [
        r"C:\keys\vision-keyvtr.json",
        r"/keys/vision-keyvtr.json",
        r"C:\keys\vision-key.json",
        r"/keys/vision-key.json",
    ]
    for path in fallback_paths:
        if os.path.exists(path):
            status["status"] = "ok"
            status["credentials"] = f"Fallback file exists: {path}"
            status["error"] = None
            return status

    # If nothing is found
    if not status["credentials"]:
        status["credentials"] = "MISSING"
        status["status"] = "error"
        
    return status

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

