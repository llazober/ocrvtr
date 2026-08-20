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
        r'\bONLINE\b', r'\bPAYMENT\b', r'\bPREAUTHORIZED\b', r'\bCONF\b', r'\bREF\b', r'\bGJ\b',
        r'\bCHECK\b', r'\bCHK\b', r'\bPAID\b'
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
            
        # Word boundary match for short patterns (e.g. WM, BP, TD, AA) or substring match for patterns
        if len(pattern) >= 2:
            if re.search(r'\b' + re.escape(pattern) + r'\b', raw_upper) or re.search(r'\b' + re.escape(pattern) + r'\b', clean_desc):
                return (acct_num, acct_name, 0.95)
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
        
    # Stage 3.5: Intelligent Banking & Vendor Heuristic Classification
    if is_deposit:
        if any(k in raw_upper for k in ["ZELLE", "VENMO", "CASH APP", "PAYPAL", "WIRE"]):
            return ("1000", "Customer Deposits / Zelle", 0.85)
        if any(k in raw_upper for k in ["ATM", "BRANCH DEPOSIT", "MOBILE DEPOSIT", "CHECK DEPOSIT", "EDEPOSIT"]):
            return ("1000", "Cash & ATM Deposits", 0.85)
        if any(k in raw_upper for k in ["MEDICAID", "GUARDIAN", "CDC PLUS", "APD", "STATE OF"]):
            return ("1000", "State / Medicaid Deposits", 0.85)
        if any(k in raw_upper for k in ["SQUARE", "STRIPE", "CLOVER", "TOAST", "SHOPIFY", "MERCHANT"]):
            return ("4000", "Merchant Sales Income", 0.85)
    else:
        # Check matching: ONLY if description is generic check text without specific vendor words
        if re.fullmatch(r'^(?:CHECK|CHK|CHECK\s*CARD|CHECK\s*PAID|CKCD|PAID\s*CHECK)(?:\s*#?\s*\d+)?$', raw_upper.strip()):
            return (default_withdrawal, "Check Payment", 0.85)

        # Expenses / Withdrawals with known vendor keywords
        if any(k in raw_upper for k in ["SANDEZ", "TRANSPORT", "FREIGHT", "TRUCKING", "LOGISTICS", "CARRIER", "SHIPPING", "EXPRESS", "DELIVERY"]):
            return ("481", "Transportation Service", 0.85)
        if any(k in raw_upper for k in ["FORD", "CHEVROLET", "AUTOZONE", "ADVANCE AUTO", "NAPA", "TIRE", "AUTOMOTIVE", "MOTORS", "CAR WASH", "AUTO"]):
            return ("725", "Auto & Vehicle Expense", 0.85)
        if any(k in raw_upper for k in ["SHELL", "CHEVRON", "EXXON", "MOBIL", "BP ", "MARATHON", "WAWA", "RACETRAC", "7-ELEVEN", "GAS STATION", "FUEL"]):
            return ("725", "Fuel & Auto Mileage", 0.85)
        if any(k in raw_upper for k in ["PUBLIX", "WALMART", "SEDANOS", "PRESIDENTE", "SUPERMARKET", "GROCERY", "TRADER JOE", "WHOLE FOODS", "CVS", "NAVARR", "WALGREENS", "TARGET", "COSTCO", "BJ'S"]):
            return ("782", "Supplies & Provisions", 0.85)
        if any(k in raw_upper for k in ["HOME DEPOT", "LOWES", "ACE HARDWARE", "REPAIR", "PLUMBING", "ROOFING", "ELECTRIC", "HARDWARE", "PAINT"]):
            return ("778", "Repairs & Maintenance", 0.85)
        if any(k in raw_upper for k in ["BAKERY", "MCDONALD", "BURGER", "PIZZA", "DELI", "CAFE", "RESTAURANT", "CHICKEN", "TACO", "SUBWAY", "DINER", "GRILL", "SUSHI", "FOOD", "BARBER"]):
            return ("748", "Meals & Entertainment", 0.85)
        if any(k in raw_upper for k in ["FPL", "DUKE", "TECO", "WATER DEPT", "CITY OF", "WASTE MGMT", "UTILITY", "AT&T", "ATT", "TMOBILE", "T-MOBILE", "VERIZON", "COMCAST", "XFINITY"]):
            return ("795", "Utilities & Telecom", 0.85)
        if any(k in raw_upper for k in ["FEE", "SERVICE CHARGE", "MAINTENANCE FEE", "OVERDRAFT", "UNCOLLECTED"]):
            return ("745", "Bank Service Charges", 0.85)
        if any(k in raw_upper for k in ["ADP", "GUSTO", "PAYCHEK", "PAYROLL", "PAYCHEX"]):
            return ("600", "Payroll Expenses", 0.85)

    # Stage 4: Safe Fallback (500/656 for withdrawals, 260 for deposits if no pattern matched)
    fallback_acc = default_deposit if is_deposit else default_withdrawal
    return (fallback_acc, "Unassigned Fallback", 0.0)
