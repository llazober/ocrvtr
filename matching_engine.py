import re
import difflib

def normalize_description(raw_desc: str) -> str:
    """
    Stage 1: Noise Removal & Text Normalization
    - Strip card mask numbers (e.g. XXXXXXXXXXXX9107 or *1234)
    - Strip store numbers (#000745862, #1364, STORE 102)
    - Strip terminal IDs, dates (03/17)
    - Strip transaction filler words (PURCHASE, CHECKCARD, CKCD, POS, DES:, ID:, DEPOSIT, WITHDRAWAL)
    - Isolate core vendor brand
    """
    if not raw_desc:
        return ""
        
    text = str(raw_desc).upper().strip()
    
    # 1. Remove card mask digits (e.g., XXXXXXXXXXXX9107, ****9107, *9107)
    text = re.sub(r'X{3,}\d*', ' ', text)
    text = re.sub(r'\*+\d*', ' ', text)
    
    # 2. Remove dates like 03/17, 01/15/2026, 01-15-2026
    text = re.sub(r'\b\d{1,2}[/\-]\d{1,2}(?:[/\-]\d{2,4})?\b', ' ', text)
    
    # 3. Remove store/terminal numbers (#1234, #000745862, STORE 05, NO. 45)
    text = re.sub(r'#\s*\d+', ' ', text)
    text = re.sub(r'\b(?:STORE|ST|NO|UNIT)\s*#?\d+\b', ' ', text)
    
    # 4. Remove transaction filler keywords
    fillers = [
        r'\bCHECKCARD\b', r'\bCKCD\b', r'\bPURCHASE\b', r'\bPOS\b', r'\bDES:\b', 
        r'\bID:\b', r'\bDEPOSIT\b', r'\bWITHDRAWAL\b', r'\bTRANSFER\b', r'\bRECURRING\b',
        r'\bONLINE\b', r'\bPAYMENT\b', r'\bPREAUTHORIZED\b', r'\bCONF\b', r'\bREF\b', r'\bGJ\b'
    ]
    for f in fillers:
        text = re.sub(f, ' ', text, flags=re.IGNORECASE)
        
    # 5. Remove city/state trailing zip codes (e.g., MIAMI FL 33168 or DELRAY BEACH FL) at end of string
    text = re.sub(r'\s+(?:MIAMI|ORLANDO|TAMPA|FORT LAUDERDALE|HIALEAH|JACKSONVILLE|WILMINGTON)?\s*(?:FL|NY|CA|TX|GA|NC|DE|NJ|IL|PA|OH|VA|WA)\b(?:\s+\d{5})?\s*$', '', text)
    text = re.sub(r'\b\d{5}(?:-\d{4})?\b', ' ', text)
    
    # 6. Clean up whitespace and non-alphanumeric punctuation except & or '
    text = re.sub(r'[^A-Z0-9\s&\'\-]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text if text else raw_desc.upper().strip()

def match_gl_account(
    raw_desc: str, 
    history_rules: list[dict], 
    default_deposit: str = "260", 
    default_withdrawal: str = "500", 
    is_deposit: bool = False
) -> tuple[str, str, float]:
    """
    4-Stage Cleaning & Matching Engine
    Returns (account_number, account_name, confidence_score)
    """
    if not raw_desc or not str(raw_desc).strip():
        fallback_acc = default_deposit if is_deposit else default_withdrawal
        return (fallback_acc, "Unassigned", 0.0)

    clean_desc = normalize_description(raw_desc)
    raw_upper = str(raw_desc).upper().strip()
    
    # If no history rules provided, return safe fallback
    if not history_rules:
        fallback_acc = default_deposit if is_deposit else default_withdrawal
        return (fallback_acc, "Unassigned", 0.0)
        
    # Stage 2: Substring & Token Matching
    for rule in history_rules:
        pattern = str(rule.get("pattern", "")).upper().strip()
        acct_num = str(rule.get("accountNumber", "")).strip()
        acct_name = rule.get("accountName", "") or "Mapped Account"
        
        if not pattern or not acct_num:
            continue
            
        # Exact match
        if clean_desc == pattern or raw_upper == pattern:
            return (acct_num, acct_name, 1.0)
            
        # Substring containment: pattern is inside clean_desc or raw_upper
        if len(pattern) >= 3 and (pattern in clean_desc or pattern in raw_upper):
            return (acct_num, acct_name, 0.95)
            
    # Stage 3: Fuzzy Close-Matching (Similarity Algorithm)
    best_match = None
    highest_ratio = 0.0
    
    for rule in history_rules:
        pattern = str(rule.get("pattern", "")).upper().strip()
        if not pattern:
            continue
            
        ratio1 = difflib.SequenceMatcher(None, clean_desc, pattern).ratio()
        ratio2 = difflib.SequenceMatcher(None, raw_upper, pattern).ratio()
        
        max_r = max(ratio1, ratio2)
        if max_r > highest_ratio:
            highest_ratio = max_r
            best_match = rule
            
    if highest_ratio >= 0.70 and best_match:
        acct_num = str(best_match.get("accountNumber", "")).strip()
        acct_name = best_match.get("accountName", "") or "Fuzzy Mapped Account"
        return (acct_num, acct_name, round(highest_ratio, 2))
        
    # Stage 3.5: Intelligent Banking Keyword Fallbacks
    if is_deposit:
        if any(k in raw_upper for k in ["ZELLE", "VENMO", "CASH APP", "PAYPAL", "WIRE"]):
            return ("1000", "Customer Deposits / Cash", 0.80)
        if any(k in raw_upper for k in ["MEDICAID", "GUARDIAN", "CDC PLUS", "APD", "STATE OF"]):
            return ("1000", "State / Medicaid Deposits", 0.85)
        if any(k in raw_upper for k in ["SQUARE", "STRIPE", "CLOVER", "TOAST", "SHOPIFY", "MERCHANT"]):
            return ("4000", "Merchant Sales Income", 0.85)
    else:
        if any(k in raw_upper for k in ["FEE", "SERVICE CHARGE", "MAINTENANCE", "OVERDRAFT", "UNCOLLECTED"]):
            return ("745", "Bank Service Charges", 0.85)
        if any(k in raw_upper for k in ["ADP", "GUSTO", "PAYCHEK", "PAYROLL", "PAYCHEX"]):
            return ("600", "Payroll Expenses", 0.85)
        if any(k in raw_upper for k in ["FPL", "DUKE", "TECO", "WATER DEPT", "CITY OF", "WASTE MGMT"]):
            return ("795", "Utilities", 0.85)
        if any(k in raw_upper for k in ["SUNPASS", "E-ZPASS", "TOLL"]):
            return ("725", "Auto & Travel", 0.85)
        if any(k in raw_upper for k in ["SHELL", "CHEVRON", "EXXON", "MOBIL", "BP ", "MARATHON", "WAWA", "RACETRAC"]):
            return ("725", "Auto Mileage & Fuel", 0.85)

    # Stage 4: Safe Fallback
    fallback_acc = default_deposit if is_deposit else default_withdrawal
    return (fallback_acc, "Unassigned Fallback", 0.0)
