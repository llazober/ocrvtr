import os
import shutil
import tempfile
from fastapi import FastAPI, File, UploadFile, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.exceptions import HTTPException
from extractor import run_extraction

app = FastAPI(title="Bank Statement OCR Extractor")

# Setup templates directory
templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
templates = Jinja2Templates(directory=templates_dir)

def cleanup_temp_dir(path: str):
    if os.path.exists(path):
        try:
            shutil.rmtree(path)
            print(f"Cleaned up temporary directory: {path}")
        except Exception as e:
            print(f"Failed to clean up temporary directory {path}: {e}")

@app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/process")
async def process_pdf(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    # Validate file extension
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")
        
    # Create unique temporary directory
    temp_dir = tempfile.mkdtemp()
    
    # Save uploaded PDF to the temp directory
    pdf_path = os.path.join(temp_dir, "input.pdf")
    try:
        with open(pdf_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        cleanup_temp_dir(temp_dir)
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")
        
    try:
        # Run the extraction pipeline (no CSV created)
        result_data = run_extraction(pdf_path, temp_dir, create_csv=False)
        
        # Add cleanup of the entire temp directory to background tasks so it runs after response is sent
        background_tasks.add_task(cleanup_temp_dir, temp_dir)
        
        return result_data
    except Exception as e:
        # If something fails, clean up immediately and raise error
        cleanup_temp_dir(temp_dir)
        raise HTTPException(status_code=500, detail=f"Extraction failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
