import os
import sys
import re
import glob
import statistics
import json
import pandas as pd
import fitz  # PyMuPDF
from google.cloud import vision
from google.oauth2 import service_account

CSV_OUTPUT = "Bank_Details.csv"

def get_vision_client():
    creds_json = os.environ.get("GOOGLE_CREDENTIALS_JSON")
    if creds_json:
        # Strip surrounding whitespace or accidental wrapping quotes
        creds_json = creds_json.strip().strip('"\'')
        try:
            info = json.loads(creds_json)
            credentials = service_account.Credentials.from_service_account_info(info)
            print("--> Initialized Google Cloud Vision client using GOOGLE_CREDENTIALS_JSON env var.")
            return vision.ImageAnnotatorClient(credentials=credentials)
        except json.JSONDecodeError as e:
            print(f"ERROR: GOOGLE_CREDENTIALS_JSON is not valid JSON: {e}")
            print(f"  First 200 chars of value: {creds_json[:200]}")
            raise RuntimeError(f"GOOGLE_CREDENTIALS_JSON env var is not valid JSON: {e}")
        except Exception as e:
            print(f"ERROR: Failed to build Vision client from GOOGLE_CREDENTIALS_JSON: {e}")
            raise RuntimeError(f"Failed to initialize Vision client from credentials: {e}")

    # Fallback: local key file (development only)
    env_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if env_path and os.path.exists(env_path):
        print(f"--> Using GOOGLE_APPLICATION_CREDENTIALS file: {env_path}")
        return vision.ImageAnnotatorClient()

    fallback_paths = [
        r"C:\keys\vision-keyvtr.json",
        r"/keys/vision-keyvtr.json",
        r"C:\keys\vision-key.json",
        r"/keys/vision-key.json",
    ]
    for path in fallback_paths:
        if os.path.exists(path):
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = path
            print(f"--> Set GOOGLE_APPLICATION_CREDENTIALS to: {path}")
            return vision.ImageAnnotatorClient()

    raise RuntimeError(
        "No Google credentials found. Set the GOOGLE_CREDENTIALS_JSON environment variable "
        "with the full contents of your service account JSON key."
    )

def sanitize_filename(name):
    if not name:
        return None
    # Remove chars not allowed in Windows/Linux filenames
    name_clean = re.sub(r'[\\/*?:"<>|]', '', name)
    # Replace multiple spaces with a single space
    name_clean = re.sub(r'\s+', ' ', name_clean)
    name_clean = name_clean.strip()
    return name_clean if name_clean else None

def extract_business_name(words):
    # Only keep words in the top half of page 1
    top_words = [w for w in words if w['center_y'] < 500]
    if not top_words:
        return None
        
    # Group words into horizontal lines
    sorted_words = sorted(top_words, key=lambda w: w['center_y'])
    lines = []
    for w in sorted_words:
        placed = False
        for line in lines:
            avg_y = sum(item['center_y'] for item in line) / len(line)
            if abs(w['center_y'] - avg_y) <= 8:
                line.append(w)
                placed = True
                break
        if not placed:
            lines.append([w])
            
    # Split each line into horizontal chunks
    chunks = []
    for line in lines:
        sorted_line = sorted(line, key=lambda w: w['center_x'])
        if not sorted_line:
            continue
            
        current_chunk = [sorted_line[0]]
        for w in sorted_line[1:]:
            gap = w['x_min'] - current_chunk[-1]['x_max']
            if gap > 80:  # Horizontal gap threshold
                chunks.append(current_chunk)
                current_chunk = [w]
            else:
                current_chunk.append(w)
        if current_chunk:
            chunks.append(current_chunk)
            
    # Process chunks to get text, coordinates
    processed_chunks = []
    for chunk in chunks:
        text = ' '.join(w['text'] for w in chunk).strip()
        min_x = min(w['x_min'] for w in chunk)
        max_x = max(w['x_max'] for w in chunk)
        avg_y = sum(w['center_y'] for w in chunk) / len(chunk)
        processed_chunks.append({
            'text': text,
            'min_x': min_x,
            'max_x': max_x,
            'y': avg_y
        })
        
    # Find the zip chunk
    zip_pattern = re.compile(r'\b\d{5}(?:-\d{4})?\b')
    zip_chunks = []
    for chunk in processed_chunks:
        txt_lower = chunk['text'].lower()
        if 'p.o. box' in txt_lower or 'po box' in txt_lower:
            pass
        if zip_pattern.search(chunk['text']) and chunk['min_x'] < 600:
            zip_chunks.append(chunk)
            
    if not zip_chunks:
        relaxed_pattern = re.compile(r'\b\d{5}\b')
        for chunk in processed_chunks:
            if relaxed_pattern.search(chunk['text']) and chunk['min_x'] < 600:
                zip_chunks.append(chunk)
                
    if not zip_chunks:
        return None
        
    zip_chunk = max(zip_chunks, key=lambda c: c['y'])
    y_zip = zip_chunk['y']
    x_zip = zip_chunk['min_x']
    
    # Find lines above the zip chunk with similar left alignment
    address_candidates = []
    for chunk in processed_chunks:
        if (y_zip - 150 < chunk['y'] < y_zip) and (abs(chunk['min_x'] - x_zip) <= 40):
            txt = chunk['text']
            txt_lower = txt.lower()
            
            # Filter out known bank names or header terms
            if any(term in txt_lower for term in [
                'bank', 'truist', 'america', 'wells fargo', 'statement', 
                'page', 'convenient', 'period', 'cust ref', 'account', 'primary'
            ]):
                continue
            # Filter out pure numbers or short codes (e.g. mail sorting codes)
            if re.match(r'^[\d\s\-C]+$', txt) or len(txt) <= 3:
                continue
                
            address_candidates.append(chunk)
            
    if not address_candidates:
        return None
        
    # Sort candidates by y (top to bottom)
    address_candidates = sorted(address_candidates, key=lambda c: c['y'])
    
    # The first candidate is the business name!
    return address_candidates[0]['text']

def convert_pdf_to_png(pdf_path, temp_dir):
    print(f"Segmenting PDF: {pdf_path}...")
    os.makedirs(temp_dir, exist_ok=True)
    
    doc = fitz.open(pdf_path)
    print(f"Total pages detected: {len(doc)}")
    
    png_paths = []
    for i, page in enumerate(doc):
        zoom = 150 / 72  # 72 is default PDF DPI
        mat = fitz.Matrix(zoom, zoom)
        pix = page.get_pixmap(matrix=mat)
        
        output_path = os.path.join(temp_dir, f"page_{i+1}.png")
        pix.save(output_path)
        print(f"  Page {i+1} saved temporarily to: {output_path}")
        png_paths.append(output_path)
        
    return png_paths

def ocr_page_to_words(client, png_path):
    print(f"Running OCR on {png_path}...")
    with open(png_path, "rb") as image_file:
        content = image_file.read()
        
    image = vision.Image(content=content)
    response = client.document_text_detection(image=image)
    
    words_data = []
    
    if not response.full_text_annotation:
        print(f"  Warning: No text detected in {png_path}")
        return words_data
        
    for page in response.full_text_annotation.pages:
        for block in page.blocks:
            for paragraph in block.paragraphs:
                for word in paragraph.words:
                    word_text = "".join([symbol.text for symbol in word.symbols])
                    
                    vertices = word.bounding_box.vertices
                    xs = [v.x for v in vertices if v.x is not None]
                    ys = [v.y for v in vertices if v.y is not None]
                    
                    if not xs or not ys:
                        continue
                        
                    x_min, x_max = min(xs), max(xs)
                    y_min, y_max = min(ys), max(ys)
                    
                    words_data.append({
                        "text": word_text,
                        "x_min": x_min,
                        "x_max": x_max,
                        "y_min": y_min,
                        "y_max": y_max,
                        "center_x": (x_min + x_max) / 2,
                        "center_y": (y_min + y_max) / 2
                    })
                    
    return words_data

def estimate_skew(words):
    # Agrupar groseramente en líneas con y_tol=25
    sorted_words = sorted(words, key=lambda w: w['center_y'])
    lines = []
    for w in sorted_words:
        placed = False
        for line in lines:
            avg_y = sum(item['center_y'] for item in line) / len(line)
            if abs(w['center_y'] - avg_y) <= 25:
                line.append(w)
                placed = True
                break
        if not placed:
            lines.append([w])
            
    slopes = []
    for line in lines:
        if len(line) >= 4:
            sorted_line = sorted(line, key=lambda w: w['center_x'])
            w_first = sorted_line[0]
            w_last = sorted_line[-1]
            dx = w_last['center_x'] - w_first['center_x']
            dy = w_last['center_y'] - w_first['center_y']
            if dx > 300:
                slopes.append(dy / dx)
    return statistics.median(slopes) if slopes else 0.0

def group_words_into_lines(words, y_tol=8):
    sorted_words = sorted(words, key=lambda w: w['center_y'])
    lines = []
    for w in sorted_words:
        placed = False
        for line in lines:
            avg_y = sum(item['center_y'] for item in line) / len(line)
            if abs(w['center_y'] - avg_y) <= y_tol:
                line.append(w)
                placed = True
                break
        if not placed:
            lines.append([w])
            
    sorted_lines = []
    for line in lines:
        sorted_line = sorted(line, key=lambda w: w['center_x'])
        avg_y = sum(w['center_y'] for w in sorted_line) / len(sorted_line)
        text = ' '.join(w['text'] for w in sorted_line)
        sorted_lines.append((avg_y, text))
    return sorted(sorted_lines, key=lambda x: x[0])

def parse_amount(line):
    # Try to find common OCR misreadings of trailing '1'
    line_clean = re.sub(r'(\d+[\.,]\d)\s*[\*l\|/iI\\]', r'\g<1>1', line)
    
    # 1. Try to find standard two-decimal amount:
    matches = re.findall(r'\b\d{1,3}(?:,\d{3})*\.\d{2}\b', line_clean)
    if matches:
        return float(matches[-1].replace(',', ''))
        
    # 2. Try to find a decimal number with 1 decimal digit:
    matches_1dec = re.findall(r'\b\d{1,3}(?:,\d{3})*\.\d{1}\b', line_clean)
    if matches_1dec:
        return float(matches_1dec[-1].replace(',', ''))
        
    # 3. Try to find any decimal:
    matches_any_dec = re.findall(r'\d+(?:,\d{3})*\.\d+', line_clean)
    if matches_any_dec:
        return float(matches_any_dec[-1].replace(',', ''))
        
    return None

def clean_check_line(line):
    cleaned = re.sub(r'[^\w\s/\.\,\-]', '', line)
    match = re.search(r'(\d{2}/\d{2})\s+(\d+)\-?\s+(\d+(?:,\d{3})*\.\d{2})', cleaned)
    if match:
        return {
            'date': match.group(1),
            'check_number': match.group(2),
            'amount': float(match.group(3).replace(',', ''))
        }
    return None

def parse_standard_section(lines):
    transactions = []
    current_tx = None
    
    for y, text in lines:
        # Robust transaction pattern matching 1 or 2 decimal digits
        match = re.match(r'^(\d{2}/\d{2})\s+(\d{1,3}(?:,\d{3})*\.\d{1,2})\s+(.*)$', text)
        if match:
            date = match.group(1)
            amount = float(match.group(2).replace(',', ''))
            rest = match.group(3).strip()
            
            current_tx = {
                'date': date,
                'amount': amount,
                'description': rest
            }
            transactions.append(current_tx)
        else:
            # If it's not a transaction line, check if it is a header line to ignore
            if any(h in text for h in ['Date posted', 'Date', 'posted', 'Amount', 'description', 'Reference', 'number', 'Transactions', 'continued']):
                if not any(k in text for k in ['PNC Merchant Deposit', 'ATM Deposit', 'POS Purchase', 'Zelle From', 'Zelle To']):
                    continue
                    
            if current_tx and not any(k in text for k in ['Total', 'Subtotal', 'balance']):
                current_tx['description'] += " " + text.strip()
                
    return transactions

def save_dataframe_to_csv(df, filepath):
    if not filepath:
        return
    dir_path = os.path.dirname(filepath)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
        
    df.to_csv(filepath, index=False, encoding='utf-8')
    print(f"--> Consolidated transactions successfully exported to '{filepath}' ({len(df)} records)")

def format_df_to_standard_columns(df):
    formatted_rows = []
    if not df.empty:
        for _, row in df.iterrows():
            cat = str(row.get('category', '')).strip()
            amt = row.get('amount', 0.0)
            
            chk = ''
            desc = str(row.get('description', '')).strip()
            
            if desc.startswith('Check '):
                m = re.match(r'^Check\s+(\d+)\s*(.*)$', desc)
                if m:
                    chk = m.group(1)
                    desc = m.group(2).strip()
                    if not desc:
                        desc = "Check"
                        
            is_deposit = False
            if cat in [
                "Deposits/Credits", "ATM Deposits and Additions", "Other Additions", "Deposits", 
                "Deposits and other credits", "Electronic Deposits", "Deposits, credits and interest"
            ]:
                is_deposit = True
                
            dep_val = amt if is_deposit else None
            wit_val = amt if not is_deposit else None
            
            formatted_rows.append({
                'date': row['date'],
                'checknumber': chk,
                'description': desc,
                'Deposits': dep_val,
                'Withdrawals': wit_val
            })
        
    res_df = pd.DataFrame(formatted_rows, columns=['date', 'checknumber', 'description', 'Deposits', 'Withdrawals'])
    return res_df

def detect_bank(p1_words):
    all_text = ' '.join(w['text'].lower() for w in p1_words)
    if 'wells fargo' in all_text or ('wells' in all_text and 'fargo' in all_text):
        return 'WELLS_FARGO'
    elif 'bank of america' in all_text or 'bankofamerica' in all_text:
        return 'BANK_OF_AMERICA'
    elif 'td bank' in all_text or 'td business' in all_text or 'tdbank' in all_text:
        return 'TD_BANK'
    elif 'truist' in all_text:
        return 'TRUIST'
    elif 'pnc' in all_text:
        return 'PNC'
    return 'PNC'

def clean_amount(val_str):
    if not val_str:
        return None
    val_str = str(val_str).strip()
    cleaned = re.sub(r'[^\d.,\-]', '', val_str)
    if not cleaned:
        return None
    match = re.search(r'[.,](\d{1,2})$', cleaned)
    if match:
        decimal_part = match.group(1)
        integer_part = cleaned[:-(len(decimal_part) + 1)]
        integer_digits = re.sub(r'[^\d\-]', '', integer_part)
        cleaned = integer_digits + '.' + decimal_part
    else:
        cleaned = re.sub(r'[^\d\-]', '', cleaned)
    try:
        return float(cleaned)
    except:
        return None

def estimate_skew_wf(words):
    slopes = []
    sorted_words = sorted(words, key=lambda w: w['center_x'])
    for i in range(len(sorted_words)):
        w1 = sorted_words[i]
        for j in range(i + 1, min(i + 15, len(sorted_words))):
            w2 = sorted_words[j]
            dx = w2['center_x'] - w1['center_x']
            dy = w2['center_y'] - w1['center_y']
            if 15 < dx < 120 and abs(dy) < 12:
                slopes.append(dy / dx)
    return statistics.median(slopes) if slopes else 0.0

def run_wells_fargo_pipeline(all_pages_words, pdf_path, csv_output=None):
    print("=== STARTING WELLS FARGO DETECTION AND PARSING ===")
    
    page_skews = {}
    non_zero_skews = []
    for page_key, words in all_pages_words.items():
        if words:
            skew = estimate_skew_wf(words)
            page_skews[page_key] = skew
            if abs(skew) > 0.0001:
                non_zero_skews.append(skew)
                
    median_skew = statistics.median(non_zero_skews) if non_zero_skews else 0.0
    
    robust_skews = {}
    for page_key, skew in page_skews.items():
        if abs(skew) <= 0.0001:
            robust_skews[page_key] = median_skew
        else:
            robust_skews[page_key] = skew
            
    summary_page = 1
    summary_totals = {}
    
    for page_key in ['page_1', 'page_2']:
        p_words = all_pages_words.get(page_key, [])
        if not p_words:
            continue
            
        p_skew = robust_skews[page_key]
        p_corr = []
        for w in p_words:
            w_c = w.copy()
            w_c['center_y'] = w['center_y'] - w['center_x'] * p_skew
            p_corr.append(w_c)
            
        p_lines = []
        for w in sorted(p_corr, key=lambda w: w['center_y']):
            placed = False
            for line in p_lines:
                avg_y = sum(item['center_y'] for item in line) / len(line)
                if abs(w['center_y'] - avg_y) <= 6:
                    line.append(w)
                    placed = True
                    break
            if not placed:
                p_lines.append([w])
                
        temp_summary = {}
        for line in sorted(p_lines, key=lambda l: sum(w['center_y'] for w in l)/len(l)):
            sorted_line = sorted(line, key=lambda w: w['center_x'])
            line_text = ' '.join(w['text'] for w in sorted_line)
            
            avg_y = sum(w['center_y'] for w in line) / len(line)
            if avg_y >= 400:
                continue
                
            matches = re.findall(r'\b\d{1,3}(?:[.,]\d{3})*[.,]\d{2}\b', line_text)
            if not matches:
                continue
            amount = clean_amount(matches[-1])
            
            lower_txt = line_text.lower()
            if 'beginning balance' in lower_txt:
                temp_summary['Beginning Balance'] = amount
            elif 'deposits' in lower_txt and 'credits' in lower_txt:
                temp_summary['Deposits/Credits'] = amount
            elif 'withdrawals' in lower_txt and 'debits' in lower_txt:
                temp_summary['Withdrawals/Debits'] = amount
            elif 'ending balance' in lower_txt:
                temp_summary['Ending Balance'] = amount
                
        if 'Beginning Balance' in temp_summary or 'Ending Balance' in temp_summary:
            summary_totals = temp_summary
            summary_page = int(page_key.split('_')[1])
            break
            
    print(f"\n=== WELLS FARGO REPORT SUMMARY (PAGE {summary_page}) ===")
    for cat, val in summary_totals.items():
        print(f"  {cat}: ${val:,.2f}")
    print()
    
    all_transactions = []
    current_date = None
    parsing_ended = False
    
    page_keys = sorted(all_pages_words.keys(), key=lambda k: int(k.split('_')[1]))
    
    for page_key in page_keys:
        page_num = int(page_key.split('_')[1])
        if page_num < summary_page:
            continue
            
        words = all_pages_words[page_key]
        if not words or parsing_ended:
            continue
            
        skew = robust_skews[page_key]
        corr_words = []
        for w in words:
            w_c = w.copy()
            w_c['y_raw'] = w['center_y']
            w_c['center_y'] = w['center_y'] - w['center_x'] * skew
            corr_words.append(w_c)
            
        if page_num == summary_page:
            y_start = 550
        else:
            y_start = 265
            
        table_words = [w for w in corr_words if w['center_y'] > y_start]
        
        lines = []
        for w in sorted(table_words, key=lambda w: w['center_y']):
            placed = False
            for line in lines:
                avg_y = sum(item['center_y'] for item in line) / len(line)
                if abs(w['center_y'] - avg_y) <= 9:
                    line.append(w)
                    placed = True
                    break
            if not placed:
                lines.append([w])
                
        active_tx = None
        for line in sorted(lines, key=lambda l: sum(w['center_y'] for w in l)/len(l)):
            full_line_str = ' '.join(w['text'] for w in sorted(line, key=lambda w: w['center_x'])).strip()
            
            if any(term in full_line_str.lower() for term in ['summary of checks', 'checks listed are also', 'service fee summary', 'totals', 'total']):
                parsing_ended = True
                break
                
            date_words = [w for w in line if w['center_x'] < 200]
            chk_words = [w for w in line if 200 <= w['center_x'] < 300]
            desc_words = [w for w in line if 300 <= w['center_x'] < 800]
            dep_words = [w for w in line if 800 <= w['center_x'] < 950]
            wit_words = [w for w in line if 950 <= w['center_x'] < 1080]
            
            date_str = ' '.join(w['text'] for w in sorted(date_words, key=lambda w: w['center_x'])).strip()
            chk_str = ' '.join(w['text'] for w in sorted(chk_words, key=lambda w: w['center_x'])).strip()
            desc_str = ' '.join(w['text'] for w in sorted(desc_words, key=lambda w: w['center_x'])).strip()
            dep_str = ' '.join(w['text'] for w in sorted(dep_words, key=lambda w: w['center_x'])).strip()
            wit_str = ' '.join(w['text'] for w in sorted(wit_words, key=lambda w: w['center_x'])).strip()
            
            if any(h in desc_str.lower() for h in ['description', 'continued', 'totals', 'ending daily']):
                continue
                
            check_num = chk_str if (chk_str.isdigit() and len(chk_str) >= 3) else None
            dep_amt = clean_amount(dep_str)
            wit_amt = clean_amount(wit_str)
            
            is_new_tx = (dep_amt is not None) or (wit_amt is not None) or (check_num is not None)
            
            if is_new_tx:
                if active_tx:
                    all_transactions.append(active_tx)
                    active_tx = None
                    
                if date_str:
                    if re.match(r'^\d{1,2}/\d{1,2}$', date_str):
                        current_date = date_str
                    elif date_str in ['5', '555', '5555555']:
                        pass
                    elif '/' in date_str:
                        m = re.search(r'(\d{1,2}/\d{1,2})', date_str)
                        if m:
                            current_date = m.group(1)
                            
                if not current_date:
                    current_date = '1/2'
                    
                category = ""
                amount = 0.0
                if dep_amt is not None:
                    category = "Deposits/Credits"
                    amount = dep_amt
                elif wit_amt is not None:
                    category = "Withdrawals/Debits"
                    amount = wit_amt
                    
                m_part, d_part = current_date.split('/')
                date_iso = f"2026-{int(m_part):02d}-{int(d_part):02d}"
                
                final_desc = desc_str
                if check_num:
                    final_desc = f"Check {check_num} {desc_str}".strip()
                    
                active_tx = {
                    'date': date_iso,
                    'amount': amount,
                    'description': final_desc,
                    'category': category
                }
            else:
                if active_tx and desc_str:
                    active_tx['description'] += " " + desc_str
                    
        if active_tx:
            all_transactions.append(active_tx)
            active_tx = None
            
        if parsing_ended:
            break
            
    for t in all_transactions:
        t['description'] = re.sub(r'\s+', ' ', t['description']).strip()
        
    df = pd.DataFrame(all_transactions)
    df = df[['date', 'amount', 'description', 'category']]
    formatted_df = format_df_to_standard_columns(df)
    save_dataframe_to_csv(formatted_df, csv_output)
    
    if len(df) > 0:
        df_sums = df.groupby('category')['amount'].sum().to_dict()
        df_counts = df.groupby('category').size().to_dict()
    else:
        df_sums = {}
        df_counts = {}
    
    reconciliation = []
    summary_dep = summary_totals.get('Deposits/Credits', 0.0)
    detail_dep = df_sums.get('Deposits/Credits', 0.0)
    reconciliation.append({
        'Category': 'Deposits/Credits',
        'Summary Amount': summary_dep,
        'Detail Sum': detail_dep,
        'Difference': detail_dep - summary_dep,
        'Items Count': df_counts.get('Deposits/Credits', 0)
    })
    
    summary_wit = summary_totals.get('Withdrawals/Debits', 0.0)
    detail_wit = df_sums.get('Withdrawals/Debits', 0.0)
    reconciliation.append({
        'Category': 'Withdrawals/Debits',
        'Summary Amount': summary_wit,
        'Detail Sum': detail_wit,
        'Difference': detail_wit - summary_wit,
        'Items Count': df_counts.get('Withdrawals/Debits', 0)
    })
    
    reconciliation_df = pd.DataFrame(reconciliation)
    print("\n=== MATHEMATICAL RECONCILIATION WITH PANDAS (WELLS FARGO) ===")
    print(reconciliation_df.to_string(index=False, formatters={
        'Summary Amount': lambda x: f"${x:,.2f}",
        'Detail Sum': lambda x: f"${x:,.2f}",
        'Difference': lambda x: f"${x:,.2f}"
    }))
    print()
    
    total_diff = reconciliation_df['Difference'].abs().sum()
    if total_diff == 0.0:
        print(f"SUCCESSFUL RECONCILIATION: The sum of details matches the Page {summary_page} summary PERFECTLY.")
    else:
        print(f"WARNING: Total difference of ${total_diff:.2f}.")
        
    return formatted_df, reconciliation

def run_pnc_pipeline(all_pages_words, pdf_path, csv_output=None):
    print("=== STARTING PNC BANK PROCESSING ===")
    
    p1_words = all_pages_words.get('page_1', [])
    if not p1_words:
        print("Error: Could not extract data from Page 1.")
        return
        
    left_p1 = [w for w in p1_words if w['center_x'] < 620]
    right_p1 = [w for w in p1_words if w['center_x'] >= 620]
    
    left_p1_lines = group_words_into_lines(left_p1, y_tol=8)
    right_p1_lines = group_words_into_lines(right_p1, y_tol=8)
    
    summary_totals = {}
    
    for y, line in left_p1_lines:
        if 'ATM Deposits' in line:
            summary_totals['ATM Deposits and Additions'] = parse_amount(line)
        elif 'Other Additions' in line and 'Deposits' not in line:
            summary_totals['Other Additions'] = parse_amount(line)
        elif line.strip().startswith('Deposits ') or line.strip() == 'Deposits' or 'Deposits' in line:
            amt = parse_amount(line)
            if amt is not None and 'ATM Deposits' not in line and 'Other' not in line:
                summary_totals['Deposits'] = amt
            
    for y, line in right_p1_lines:
        if line.startswith('Checks ') or line == 'Checks':
            amt = parse_amount(line)
            if amt is not None:
                summary_totals['Checks'] = amt
        elif 'Debit Card Purchases' in line:
            summary_totals['Debit Card Purchases'] = parse_amount(line)
        elif 'POS Purchases' in line:
            summary_totals['POS Purchases'] = parse_amount(line)
        elif 'ATM / Misc' in line or 'ATM/Misc' in line:
            summary_totals['ATM/Misc. Debit Card Transactions'] = parse_amount(line)
        elif 'ACH Deductions' in line:
            summary_totals['ACH Deductions'] = parse_amount(line)
        elif 'Service Charges' in line:
            summary_totals['Service Charges and Fees'] = parse_amount(line)
        elif 'Other Deductions' in line:
            summary_totals['Other Deductions'] = parse_amount(line)
            
    print("\n=== REPORT SUMMARY (PAGE 1) ===")
    for cat, val in summary_totals.items():
        if val is not None:
            print(f"  {cat}: ${val:,.2f}")
        else:
            print(f"  {cat}: None")
    print()

    details = []
    
    page_keys = sorted(all_pages_words.keys(), key=lambda k: int(k.split('_')[1]))
    for page_key in page_keys:
        page_num = int(page_key.split('_')[1])
        if page_num == 1:
            continue
            
        words = all_pages_words[page_key]
        if not words:
            continue
            
        skew = estimate_skew(words)
        corr_words = []
        for w in words:
            w_c = w.copy()
            w_c['center_y'] = w['center_y'] - w['center_x'] * skew
            corr_words.append(w_c)
            
        lines = group_words_into_lines(corr_words, y_tol=8)
        
        headers = []
        for y, text in lines:
            txt_lower = text.lower()
            if 'atm deposits and additions' in txt_lower or 'atm deposits' in txt_lower:
                headers.append((y, 'ATM Deposits and Additions'))
            elif 'other additions' in txt_lower:
                headers.append((y, 'Other Additions'))
            elif text.strip() == 'Deposits' or (text.strip().startswith('Deposits') and len(text.strip()) < 15):
                headers.append((y, 'Deposits'))
            elif 'checks and substitute' in txt_lower:
                headers.append((y, 'Checks'))
            elif 'debit card purchases' in txt_lower:
                headers.append((y, 'Debit Card Purchases'))
            elif 'pos purchases' in txt_lower:
                headers.append((y, 'POS Purchases'))
            elif 'atm / misc' in txt_lower or 'atm/misc' in txt_lower:
                headers.append((y, 'ATM/Misc. Debit Card Transactions'))
            elif 'ach deductions' in txt_lower:
                headers.append((y, 'ACH Deductions'))
            elif 'service charges and fees' in txt_lower or 'service charges' in txt_lower:
                headers.append((y, 'Service Charges and Fees'))
            elif 'other deductions' in txt_lower:
                headers.append((y, 'Other Deductions'))
            elif any(k in txt_lower for k in ['detail of services used', 'daily balance', 'relationship pricing', 'maintenance fee']):
                headers.append((y, 'END'))
                
        headers = sorted(headers, key=lambda h: h[0])
        
        segments = []
        for i in range(len(headers)):
            y_start, cat = headers[i]
            if cat == 'END':
                break
            y_end = 9999.0
            if i + 1 < len(headers):
                y_end = headers[i+1][0]
            segments.append((y_start, y_end, cat))
            
        for y_start, y_end, cat in segments:
            if cat == 'Checks':
                checks_words = [w for w in corr_words if y_start + 25 <= w['center_y'] < y_end]
                col1_w = [w for w in checks_words if w['center_x'] < 450]
                col2_w = [w for w in checks_words if 450 <= w['center_x'] < 790]
                col3_w = [w for w in checks_words if w['center_x'] >= 790]
                
                for col_w in [col1_w, col2_w, col3_w]:
                    col_lines = group_words_into_lines(col_w, y_tol=8)
                    for y, line in col_lines:
                        chk = clean_check_line(line)
                        if chk:
                            details.append({
                                'date': chk['date'],
                                'amount': chk['amount'],
                                'description': f"Check {chk['check_number']}",
                                'category': 'Checks'
                            })
            else:
                seg_words = [w for w in corr_words if y_start <= w['center_y'] < y_end]
                seg_lines = group_words_into_lines(seg_words, y_tol=8)
                seg_txs = parse_standard_section(seg_lines)
                for t in seg_txs:
                    t['category'] = cat
                    details.append(t)
                    
    for t in details:
        date_str = t['date'].replace('-', '')
        match = re.search(r'(\d{2})/(\d{2})', date_str)
        if match:
            t['date'] = f"2026-{match.group(1)}-{match.group(2)}"
        else:
            t['date'] = "2026-01-01"
            
        t['description'] = re.sub(r'\s+', ' ', t['description']).strip()
        
    df = pd.DataFrame(details)
    formatted_df = format_df_to_standard_columns(df)
    save_dataframe_to_csv(formatted_df, csv_output)
    
    if len(df) > 0:
        df_sums = df.groupby('category')['amount'].sum().to_dict()
        df_counts = df.groupby('category').size().to_dict()
    else:
        df_sums = {}
        df_counts = {}
    
    reconciliation = []
    for category, sum_val in summary_totals.items():
        det_sum = df_sums.get(category, 0.0)
        det_count = df_counts.get(category, 0)
        diff = det_sum - sum_val
        reconciliation.append({
            'Category': category,
            'Summary Amount': sum_val,
            'Detail Sum': det_sum,
            'Difference': diff,
            'Items Count': det_count
        })
        
    reconciliation_df = pd.DataFrame(reconciliation)
    
    if not reconciliation_df.empty:
        print("\n=== MATHEMATICAL RECONCILIATION WITH PANDAS ===")
        print(reconciliation_df.to_string(index=False, formatters={
            'Summary Amount': lambda x: f"${x:,.2f}",
            'Detail Sum': lambda x: f"${x:,.2f}",
            'Difference': lambda x: f"${x:,.2f}"
        }))
        print()
        
        total_diff = reconciliation_df['Difference'].abs().sum()
        if total_diff < 0.01:
            print("SUCCESSFUL RECONCILIATION: The sum of details matches the Page 1 summary PERFECTLY.")
        else:
            print(f"WARNING: Total difference of ${total_diff:.2f}.")
    else:
        print("\n=== NO RECONCILIATION SUMMARY DATA AVAILABLE ===")
        
    return formatted_df, reconciliation

def run_boa_pipeline(all_pages_words, pdf_path, csv_output=None):
    print("=== STARTING BANK OF AMERICA PROCESSING ===")
    
    p1_words = all_pages_words.get('page_1', [])
    if not p1_words:
        print("Error: Page 1 not found.")
        return
        
    p1_lines = group_words_into_lines(p1_words, y_tol=8)
    summary_totals = {
        'Deposits and other credits': 0.0,
        'Withdrawals and other debits': 0.0,
        'Checks': 0.0,
        'Service fees': 0.0
    }
    
    for y, line in p1_lines:
        line_clean = line.lower()
        if 'deposits and other credits' in line_clean:
            m = re.search(r'deposits and other credits\s*(-?\d{1,3}(?:,\d{3})*\.\d{2})', line_clean)
            if m:
                summary_totals['Deposits and other credits'] = abs(float(m.group(1).replace(',', '')))
        elif 'withdrawals and other debits' in line_clean:
            m = re.search(r'withdrawals and other debits\s*(-?\d{1,3}(?:,\d{3})*\.\d{2})', line_clean)
            if m:
                summary_totals['Withdrawals and other debits'] = abs(float(m.group(1).replace(',', '')))
        elif 'checks' in line_clean:
            m = re.search(r'checks\s*(-?\d{1,3}(?:,\d{3})*\.\d{2})', line_clean)
            if m:
                summary_totals['Checks'] = abs(float(m.group(1).replace(',', '')))
        elif 'service fees' in line_clean:
            m = re.search(r'service fees\s*(-?\d{1,3}(?:,\d{3})*\.\d{2})', line_clean)
            if m:
                summary_totals['Service fees'] = abs(float(m.group(1).replace(',', '')))
                
    print("\n=== REPORT SUMMARY (PAGE 1) ===")
    for cat, val in summary_totals.items():
        if val is not None:
            print(f"  {cat}: ${val:,.2f}")
        else:
            print(f"  {cat}: None")
    print()

    details = []
    
    page_keys = sorted(all_pages_words.keys(), key=lambda k: int(k.split('_')[1]))
    for page_key in page_keys:
        page_num = int(page_key.split('_')[1])
        if page_num == 1:
            continue
            
        words = all_pages_words[page_key]
        if not words:
            continue
            
        skew = estimate_skew(words)
        corr_words = []
        for w in words:
            w_c = w.copy()
            w_c['center_y'] = w['center_y'] - w['center_x'] * skew
            corr_words.append(w_c)
            
        lines = group_words_into_lines(corr_words, y_tol=8)
        
        headers = []
        for y, text in lines:
            txt_lower = text.lower()
            if 'deposits and other credits' in txt_lower:
                headers.append((y, 'Deposits and other credits'))
            elif 'withdrawals and other debits' in txt_lower:
                headers.append((y, 'Withdrawals and other debits'))
            elif text.strip().lower() == 'checks' or (text.strip().lower().startswith('checks') and len(text.strip()) < 15):
                headers.append((y, 'Checks'))
            elif 'service fees' in txt_lower:
                headers.append((y, 'Service fees'))
            elif any(k in txt_lower for k in ['daily ledger balances', 'preferred rewards', 'business advantage']):
                if y > 400:
                    headers.append((y, 'END'))
                    
        headers = sorted(headers, key=lambda h: h[0])
        
        segments = []
        for i in range(len(headers)):
            y_start, cat = headers[i]
            if cat == 'END':
                break
            y_end = 9999.0
            if i + 1 < len(headers):
                y_end = headers[i+1][0]
            segments.append((y_start, y_end, cat))
            
        for y_start, y_end, cat in segments:
            seg_words = [w for w in corr_words if y_start <= w['center_y'] < y_end]
            
            if cat == 'Checks':
                col1_words = [w for w in seg_words if w['center_x'] < 650]
                col2_words = [w for w in seg_words if w['center_x'] >= 650]
                
                for col_words in [col1_words, col2_words]:
                    col_lines = group_words_into_lines(col_words, y_tol=8)
                    current_tx = None
                    for y, text in col_lines:
                        if any(h in text for h in ['Date Description Amount', 'Subtotal for card', 'Total withdrawals', 'Average ledger', 'Total checks', 'Total # of checks']):
                            continue
                        match_chk = re.match(r'^(\d{2}/\d{2}/\d{2})\s+(\d+)\s+(-?\d{1,3}(?:,\d{3})*\.\d{2})$', text)
                        if match_chk:
                            date = match_chk.group(1)
                            chk_num = match_chk.group(2)
                            amount = clean_amount(match_chk.group(3))
                            
                            current_tx = {
                                'date': date,
                                'amount': amount,
                                'description': f"Check {chk_num}",
                                'category': 'Checks'
                            }
                            details.append(current_tx)
                        else:
                            if current_tx and not any(k in text for k in ['Total', 'Subtotal', 'balance']):
                                current_tx['description'] += " " + text.strip()
            else:
                seg_lines = group_words_into_lines(seg_words, y_tol=8)
                current_tx = None
                for y, text in seg_lines:
                    if any(h in text for h in ['Date Description Amount', 'Subtotal for card', 'Total withdrawals', 'Average ledger']):
                        continue
                    if text.strip().startswith('Card account #'):
                        continue
                        
                    match = re.match(r'^(\d{2}/\d{2}/\d{2})\s+(.*)\s+(-?\d{1,3}(?:,\d{3})*\.\d{2})$', text)
                    if match:
                        date = match.group(1)
                        desc = match.group(2).strip()
                        amount = clean_amount(match.group(3))
                        
                        current_tx = {
                            'date': date,
                            'amount': amount,
                            'description': desc,
                            'category': cat
                        }
                        details.append(current_tx)
                    else:
                        if current_tx and not any(k in text for k in ['Total', 'Subtotal', 'balance']):
                            current_tx['description'] += " " + text.strip()
                            
    for t in details:
        date_str = t['date'].replace('-', '')
        match = re.search(r'(\d{2})/(\d{2})/(\d{2})', date_str)
        if match:
            t['date'] = f"20{match.group(3)}-{match.group(1)}-{match.group(2)}"
        else:
            match_short = re.search(r'(\d{2})/(\d{2})', date_str)
            if match_short:
                t['date'] = f"2026-{match_short.group(1)}-{match_short.group(2)}"
            else:
                t['date'] = "2026-01-01"
                
        t['description'] = re.sub(r'\s+', ' ', t['description']).strip()
        
    df = pd.DataFrame(details)
    formatted_df = format_df_to_standard_columns(df)
    save_dataframe_to_csv(formatted_df, csv_output)
    
    if len(df) > 0:
        df_sums = df.groupby('category')['amount'].sum().to_dict()
        df_counts = df.groupby('category').size().to_dict()
    else:
        df_sums = {}
        df_counts = {}
        
    reconciliation = []
    for category, sum_val in summary_totals.items():
        det_sum = df_sums.get(category, 0.0)
        det_count = df_counts.get(category, 0)
        diff = det_sum - sum_val
        reconciliation.append({
            'Category': category,
            'Summary Amount': sum_val,
            'Detail Sum': det_sum,
            'Difference': diff,
            'Items Count': det_count
        })
        
    reconciliation_df = pd.DataFrame(reconciliation)
    
    if not reconciliation_df.empty:
        print("\n=== MATHEMATICAL RECONCILIATION WITH PANDAS ===")
        print(reconciliation_df.to_string(index=False, formatters={
            'Summary Amount': lambda x: f"${x:,.2f}",
            'Detail Sum': lambda x: f"${x:,.2f}",
            'Difference': lambda x: f"${x:,.2f}"
        }))
        print()
        
        total_diff = reconciliation_df['Difference'].abs().sum()
        if total_diff < 0.01:
            print("SUCCESSFUL RECONCILIATION: The sum of details matches the Page 1 summary PERFECTLY.")
        else:
            print(f"WARNING: Total difference of ${total_diff:.2f}.")
    else:
        print("\n=== NO RECONCILIATION SUMMARY DATA AVAILABLE ===")
        
    return formatted_df, reconciliation

def run_td_pipeline(all_pages_words, pdf_path, csv_output=None):
    print("=== STARTING TD BANK PROCESSING ===")
    
    p1_words = all_pages_words.get('page_1', [])
    if not p1_words:
        print("Error: Page 1 not found.")
        return
        
    p1_text = ' '.join(w['text'] for w in p1_words)
    months_pattern = r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)'
    period_match = re.search(
        months_pattern + r'\s+\d{1,2}\s+(\d{4})\s*-\s*' + months_pattern + r'\s+\d{1,2}\s+(\d{4})',
        p1_text.lower()
    )
    start_year, end_year = 2025, 2025
    start_month, end_month = 1, 2
    if period_match:
        start_year = int(period_match.group(2))
        end_year = int(period_match.group(4))
        months_map = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
        start_month = months_map.get(period_match.group(1), 1)
        end_month = months_map.get(period_match.group(3), 2)
        
    def get_date_iso(date_str):
        m = re.match(r'(\d{2})/(\d{2})', date_str)
        if not m:
            return "2025-01-01"
        month = int(m.group(1))
        day = int(m.group(2))
        year = start_year if month == start_month else end_year
        return f"{year}-{month:02d}-{day:02d}"

    left_p1 = [w for w in p1_words if w['center_x'] < 600 and w['center_y'] < 800]
    left_p1_lines = group_words_into_lines(left_p1, y_tol=8)
    summary_totals = {
        'Electronic Deposits': 0.0,
        'Electronic Payments': 0.0,
        'Service Charges': 0.0
    }
    for y, line in left_p1_lines:
        line_clean = line.lower()
        if 'electronic deposits' in line_clean:
            amt = clean_amount(line.split('Deposits')[-1])
            if amt: summary_totals['Electronic Deposits'] = amt
        elif 'electronic payments' in line_clean:
            amt = clean_amount(line.split('Payments')[-1])
            if amt: summary_totals['Electronic Payments'] = amt
        elif 'service charges' in line_clean:
            amt = clean_amount(line.split('Charges')[-1])
            if amt: summary_totals['Service Charges'] = amt
            
    print("\n=== REPORT SUMMARY (PAGE 1) ===")
    for cat, val in summary_totals.items():
        print(f"  {cat}: ${val:,.2f}")
    print()
    
    details = []
    active_cat = None
    
    page_keys = sorted(all_pages_words.keys(), key=lambda k: int(k.split('_')[1]))
    for page_key in page_keys:
        page_num = int(page_key.split('_')[1])
        words = all_pages_words[page_key]
        if not words:
            continue
            
        if page_num == 1:
            page_words = [w for w in words if w['center_y'] >= 800]
        else:
            page_words = [w for w in words if 400 <= w['center_y'] < 1450]
            
        if not page_words:
            continue
            
        skew = estimate_skew(page_words)
        corr_words = []
        for w in page_words:
            w_c = w.copy()
            w_c['center_y'] = w['center_y'] - w['center_x'] * skew
            corr_words.append(w_c)
            
        lines = group_words_into_lines(corr_words, y_tol=8)
        
        headers = []
        for y, text in lines:
            txt_lower = text.lower()
            if 'electronic deposits' in txt_lower and 'summary' not in txt_lower and 'subtotal' not in txt_lower:
                headers.append((y, 'Electronic Deposits'))
            elif 'electronic payments' in txt_lower and 'summary' not in txt_lower and 'subtotal' not in txt_lower:
                headers.append((y, 'Electronic Payments'))
            elif 'service charges' in txt_lower and 'summary' not in txt_lower and 'subtotal' not in txt_lower:
                headers.append((y, 'Service Charges'))
            elif 'daily balance summary' in txt_lower:
                headers.append((y, 'END'))
        
        headers = sorted(headers, key=lambda h: h[0])
        segments = []
        
        prev_y = 0.0
        for y, cat in headers:
            if active_cat and y > prev_y:
                segments.append((prev_y, y, active_cat))
            prev_y = y
            active_cat = cat if cat != 'END' else None
            
        if active_cat and prev_y < 9999.0:
            segments.append((prev_y, 9999.0, active_cat))
            
        for y_start, y_end, cat in segments:
            seg_words = [w for w in corr_words if y_start <= w['center_y'] < y_end]
            
            date_words = [w for w in seg_words if w['center_x'] < 250]
            date_lines = group_words_into_lines(date_words, y_tol=8)
            dates = []
            for y_d, txt_d in date_lines:
                txt_clean = txt_d.replace(' ', '')
                if re.match(r'^\d{2}/\d{2}$', txt_clean):
                    dates.append({'y': y_d, 'text': txt_clean})
                    
            amt_words = [w for w in seg_words if w['center_x'] >= 1000]
            amt_lines = group_words_into_lines(amt_words, y_tol=8)
            amounts = []
            for y_a, txt_a in amt_lines:
                val = clean_amount(txt_a)
                if val is not None:
                    closest_line = min(lines, key=lambda l: abs(l[0] - y_a))
                    closest_txt_lower = closest_line[1].lower()
                    if any(k in closest_txt_lower for k in ['subtotal', 'total', 'balance', 'page', 'carried forward', 'brought forward']):
                        continue
                    amounts.append({'y': y_a, 'value': val})
                    
            if len(dates) == len(amounts) and len(dates) > 0:
                for i in range(len(dates)):
                    y_min = (dates[i-1]['y'] + dates[i]['y'])/2 if i > 0 else y_start
                    y_max = (dates[i]['y'] + dates[i+1]['y'])/2 if i+1 < len(dates) else y_end
                    
                    desc_w = [w for w in seg_words if 250 <= w['center_x'] < 1000 and y_min <= w['center_y'] < y_max]
                    desc_lines = group_words_into_lines(desc_w, y_tol=8)
                    desc_str = ' '.join(line_txt for _, line_txt in desc_lines).strip()
                    
                    details.append({
                        'date': get_date_iso(dates[i]['text']),
                        'amount': amounts[i]['value'],
                        'description': desc_str,
                        'category': cat
                    })
                
    df = pd.DataFrame(details)
    formatted_df = format_df_to_standard_columns(df)
    save_dataframe_to_csv(formatted_df, csv_output)
    
    if len(df) > 0:
        df_sums = df.groupby('category')['amount'].sum().to_dict()
        df_counts = df.groupby('category').size().to_dict()
    else:
        df_sums = {}
        df_counts = {}
        
    reconciliation = []
    for category, sum_val in summary_totals.items():
        det_sum = df_sums.get(category, 0.0)
        det_count = df_counts.get(category, 0)
        diff = det_sum - sum_val
        reconciliation.append({
            'Category': category,
            'Summary Amount': sum_val,
            'Detail Sum': det_sum,
            'Difference': diff,
            'Items Count': det_count
        })
        
    reconciliation_df = pd.DataFrame(reconciliation)
    
    if not reconciliation_df.empty:
        print("\n=== MATHEMATICAL RECONCILIATION WITH PANDAS (TD BANK) ===")
        print(reconciliation_df.to_string(index=False, formatters={
            'Summary Amount': lambda x: f"${x:,.2f}",
            'Detail Sum': lambda x: f"${x:,.2f}",
            'Difference': lambda x: f"${x:,.2f}"
        }))
        print()
        
        total_diff = reconciliation_df['Difference'].abs().sum()
        if total_diff < 0.01:
            print("SUCCESSFUL RECONCILIATION: The sum of details matches the Page 1 summary PERFECTLY.")
        else:
            print(f"WARNING: Total difference of ${total_diff:.2f}.")
    else:
        print("\n=== NO RECONCILIATION SUMMARY DATA AVAILABLE ===")
        
    return formatted_df, reconciliation

def run_truist_pipeline(all_pages_words, pdf_path, csv_output=None):
    print("=== STARTING TRUIST BANK PROCESSING ===")
    
    p1_words = all_pages_words.get('page_1', [])
    if not p1_words:
        print("Error: Page 1 not found.")
        return
        
    p1_text = ' '.join(w['text'] for w in p1_words)
    year = 2025
    for_match = re.search(r'for\s+\d{2}/\d{2}/(\d{4})', p1_text.lower())
    if for_match:
        year = int(for_match.group(1))
        
    def get_date_iso(date_str):
        m = re.match(r'(\d{2})/(\d{2})', date_str)
        if not m:
            return "2025-01-01"
        month = int(m.group(1))
        day = int(m.group(2))
        return f"{year}-{month:02d}-{day:02d}"

    left_words = [w for w in p1_words if w['center_x'] < 400 and w['center_y'] < 800]
    right_words = [w for w in p1_words if 400 <= w['center_x'] < 700 and w['center_y'] < 800]
    left_lines = group_words_into_lines(left_words, y_tol=8)
    right_lines = group_words_into_lines(right_words, y_tol=8)
    
    y_summary_start = None
    y_checks_start = None
    for w in p1_words:
        w_lower = w['text'].lower()
        if w_lower == 'summary' and w['center_x'] < 300:
            y_summary_start = w['center_y']
        if w_lower == 'checks' and w['center_x'] < 300:
            y_checks_start = w['center_y']
            
    summary_totals = {
        'Checks': 0.0,
        'Other withdrawals, debits and service charges': 0.0,
        'Deposits, credits and interest': 0.0
    }
    if y_summary_start is not None and y_checks_start is not None:
        lbl_lines = [(y, txt) for y, txt in left_lines if y_summary_start <= y < y_checks_start]
        val_lines = [(y, txt) for y, txt in right_lines if y_summary_start <= y < y_checks_start]
        
        for lbl_y, lbl_txt in lbl_lines:
            lbl_clean = lbl_txt.lower()
            if not val_lines: continue
            closest_val = min(val_lines, key=lambda v: abs(v[0] - lbl_y))
            val = clean_amount(closest_val[1])
            if 'checks' in lbl_clean:
                summary_totals['Checks'] = val
            elif 'other withdrawals' in lbl_clean:
                summary_totals['Other withdrawals, debits and service charges'] = val
            elif 'deposits' in lbl_clean:
                summary_totals['Deposits, credits and interest'] = val
                
    print("\n=== REPORT SUMMARY (PAGE 1) ===")
    for cat, val in summary_totals.items():
        print(f"  {cat}: ${val:,.2f}")
    print()
    
    details = []
    active_cat = None
    
    page_keys = sorted(all_pages_words.keys(), key=lambda k: int(k.split('_')[1]))
    for page_key in page_keys:
        page_num = int(page_key.split('_')[1])
        words = all_pages_words[page_key]
        if not words:
            continue
            
        if page_num == 1:
            page_words = [w for w in words if w['center_y'] >= 800]
        else:
            page_words = [w for w in words if 100 <= w['center_y'] < 1550]
            
        if not page_words:
            continue
            
        skew = estimate_skew_wf(page_words)
        corr_words = []
        for w in page_words:
            w_c = w.copy()
            w_c['center_y'] = w['center_y'] - w['center_x'] * skew
            corr_words.append(w_c)
            
        lines = group_words_into_lines(corr_words, y_tol=8)
        
        headers = []
        for y, text in lines:
            txt_lower = text.lower()
            txt_clean_header = re.sub(r'\s*,\s*', ',', txt_lower)
            if text.strip() == 'Checks' or (text.strip().startswith('Checks') and len(text.strip()) < 15):
                headers.append((y, 'Checks'))
            elif 'other withdrawals' in txt_clean_header and 'debits' in txt_clean_header:
                headers.append((y, 'Other withdrawals, debits and service charges'))
            elif 'deposits' in txt_clean_header and 'credits' in txt_clean_header and 'interest' in txt_clean_header:
                headers.append((y, 'Deposits, credits and interest'))
            elif 'daily balance summary' in txt_clean_header:
                headers.append((y, 'END'))
                
        headers = sorted(headers, key=lambda h: h[0])
        segments = []
        
        prev_y = 0.0
        for y, cat in headers:
            if active_cat and y > prev_y:
                segments.append((prev_y, y, active_cat))
            prev_y = y
            active_cat = cat if cat != 'END' else None
            
        if active_cat and prev_y < 9999.0:
            segments.append((prev_y, 9999.0, active_cat))
            
        for y_start, y_end, cat in segments:
            if cat == 'Checks':
                checks_words = [w for w in corr_words if y_start <= w['center_y'] < y_end]
                col1_w = [w for w in checks_words if w['center_x'] < 440]
                col2_w = [w for w in checks_words if 440 <= w['center_x'] < 850]
                col3_w = [w for w in checks_words if w['center_x'] >= 850]
                
                for col_w in [col1_w, col2_w, col3_w]:
                    col_lines = group_words_into_lines(col_w, y_tol=8)
                    for y, line in col_lines:
                        if any(h in line for h in ['DATE', 'CHECK', 'AMOUNT', 'Total', 'checks']):
                            continue
                        match_chk = re.match(r'^(\d{2}/\d{2})\s+(\d+)\s+(\d{1,3}(?:,\d{3})*\.\d{2})$', line)
                        if match_chk:
                            date_str = match_chk.group(1)
                            chk_num = match_chk.group(2)
                            amount = clean_amount(match_chk.group(3))
                            details.append({
                                'date': get_date_iso(date_str),
                                'amount': amount,
                                'description': f"Check {chk_num}",
                                'category': 'Checks'
                            })
            else:
                seg_words = [w for w in corr_words if y_start <= w['center_y'] < y_end]
                
                date_words = [w for w in seg_words if w['center_x'] < 100]
                date_lines = group_words_into_lines(date_words, y_tol=8)
                dates = []
                for y_d, txt_d in date_lines:
                    txt_clean = txt_d.replace(' ', '')
                    if re.match(r'^\d{2}/\d{2}$', txt_clean):
                        dates.append({'y': y_d, 'text': txt_clean})
                        
                amt_words = [w for w in seg_words if w['center_x'] >= 1000]
                amt_lines = group_words_into_lines(amt_words, y_tol=8)
                amounts = []
                for y_a, txt_a in amt_lines:
                    val = clean_amount(txt_a)
                    if val is not None:
                        closest_line = min(lines, key=lambda l: abs(l[0] - y_a))
                        closest_txt_lower = closest_line[1].lower()
                        if any(k in closest_txt_lower for k in ['subtotal', 'total', 'balance', 'page', 'carried forward', 'brought forward']):
                            continue
                        amounts.append({'y': y_a, 'value': val})
                        
                if len(dates) == len(amounts) and len(dates) > 0:
                    for i in range(len(dates)):
                        y_min = (dates[i-1]['y'] + dates[i]['y'])/2 if i > 0 else y_start
                        y_max = (dates[i]['y'] + dates[i+1]['y'])/2 if i+1 < len(dates) else y_end
                        
                        desc_w = [w for w in seg_words if 100 <= w['center_x'] < 1000 and y_min <= w['center_y'] < y_max]
                        desc_lines = group_words_into_lines(desc_w, y_tol=8)
                        desc_str = ' '.join(line_txt for _, line_txt in desc_lines).strip()
                        
                        details.append({
                            'date': get_date_iso(dates[i]['text']),
                            'amount': amounts[i]['value'],
                            'description': desc_str,
                            'category': cat
                        })
                        
    df = pd.DataFrame(details)
    formatted_df = format_df_to_standard_columns(df)
    save_dataframe_to_csv(formatted_df, csv_output)
    
    if len(df) > 0:
        df_sums = df.groupby('category')['amount'].sum().to_dict()
        df_counts = df.groupby('category').size().to_dict()
    else:
        df_sums = {}
        df_counts = {}
        
    reconciliation = []
    for category, sum_val in summary_totals.items():
        det_sum = df_sums.get(category, 0.0)
        det_count = df_counts.get(category, 0)
        diff = det_sum - sum_val
        reconciliation.append({
            'Category': category,
            'Summary Amount': sum_val,
            'Detail Sum': det_sum,
            'Difference': diff,
            'Items Count': det_count
        })
        
    reconciliation_df = pd.DataFrame(reconciliation)
    
    if not reconciliation_df.empty:
        print("\n=== MATHEMATICAL RECONCILIATION WITH PANDAS (TRUIST BANK) ===")
        print(reconciliation_df.to_string(index=False, formatters={
            'Summary Amount': lambda x: f"${x:,.2f}",
            'Detail Sum': lambda x: f"${x:,.2f}",
            'Difference': lambda x: f"${x:,.2f}"
        }))
        print()
        
        total_diff = reconciliation_df['Difference'].abs().sum()
        if total_diff < 0.01:
            print("SUCCESSFUL RECONCILIATION: The sum of details matches the Page 1 summary PERFECTLY.")
        else:
            print(f"WARNING: Total difference of ${total_diff:.2f}.")
    else:
        print("\n=== NO RECONCILIATION SUMMARY DATA AVAILABLE ===")
        
    return formatted_df, reconciliation

def run_extraction(pdf_path, temp_dir, create_csv=False):
    convert_pdf_to_png(pdf_path, temp_dir)
    
    client = get_vision_client()
    
    p1_png = os.path.join(temp_dir, "page_1.png")
    if not os.path.exists(p1_png):
        raise FileNotFoundError("Could not find Page 1 image.")
        
    p1_words = ocr_page_to_words(client, p1_png)
    bank_type = detect_bank(p1_words)
    print(f"\n--> DETECTED BANK: {bank_type}")
    
    bus_name = extract_business_name(p1_words)
    csv_filename = CSV_OUTPUT
    if bus_name:
        clean_bus_name = sanitize_filename(bus_name)
        if clean_bus_name:
            csv_filename = f"{clean_bus_name}.csv"
            print(f"--> EXTRACTED BUSINESS NAME: '{bus_name}' -> Filename: '{csv_filename}'")
            
    csv_output_path = os.path.join(temp_dir, csv_filename) if create_csv else None
    
    png_files = sorted(glob.glob(os.path.join(temp_dir, "page_*.png")))
    all_pages_words = {'page_1': p1_words}
    
    for png_path in png_files:
        page_name = os.path.basename(png_path).replace(".png", "")
        if page_name == 'page_1':
            continue
        words = ocr_page_to_words(client, png_path)
        all_pages_words[page_name] = words
        
    if bank_type == 'WELLS_FARGO':
        formatted_df, reconciliation = run_wells_fargo_pipeline(all_pages_words, pdf_path, csv_output_path)
    elif bank_type == 'BANK_OF_AMERICA':
        formatted_df, reconciliation = run_boa_pipeline(all_pages_words, pdf_path, csv_output_path)
    elif bank_type == 'TD_BANK':
        formatted_df, reconciliation = run_td_pipeline(all_pages_words, pdf_path, csv_output_path)
    elif bank_type == 'TRUIST':
        formatted_df, reconciliation = run_truist_pipeline(all_pages_words, pdf_path, csv_output_path)
    else:
        formatted_df, reconciliation = run_pnc_pipeline(all_pages_words, pdf_path, csv_output_path)
        
    # Convert NaN to None for JSON compliance
    clean_df = formatted_df.astype(object).where(pd.notnull(formatted_df), None)
    return {
        "bank_type": bank_type,
        "business_name": bus_name,
        "transactions": clean_df.to_dict(orient='records'),
        "reconciliation": reconciliation
    }
