import re
from datetime import UTC, date, datetime
from itertools import pairwise

# Regex Patterns
# Malaysian IC format: YYMMDD-PP-NNNN (e.g. 900101-14-5555)
# Year: 00-99, Month: 01-12, Day: 01-31, Place: 01-99, Unique: 0000-9999
MY_IC_PATTERN = re.compile(r"\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-\d{2}-\d{4}\b")
MY_IC_COMPACT_PATTERN = re.compile(
    r"\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{6}\b"
)
MY_IC_SPACED_PATTERN = re.compile(
    r"\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[ .]\d{2}[ .]\d{4}\b"
)

# Malaysian Mobile Phone format: 01X-XXXXXXX or 01X-XXXXXXXX
MY_PHONE_PATTERN = re.compile(r"(?<!\d)(?:(?:\+?60)[ -]?|0)1\d(?:[ -]?\d){7,8}(?!\d)")

# Standard Email
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)

# Credit Card (Visa, MasterCard, Amex, Discover)
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
LABELLED_NAME_PATTERN = re.compile(r"(?im)^\s*name\s*:\s*(.{2,120})$")
LABELLED_ADDRESS_PATTERN = re.compile(r"(?im)^\s*(?:address|alamat)\s*:\s*(.{3,240})$")
LABELLED_MATRIC_PATTERN = re.compile(
    r"(?im)^\s*matric(?:ulation)?\s*(?:no\.?|number)?\s*:\s*([A-Z0-9-]{4,40})\s*$"
)
LABELLED_GOVERNMENT_ID_PATTERN = re.compile(
    r"(?im)^\s*(?:passport|driver(?:'s)?\s*licen[cs]e|student\s*id|employee\s*id|"
    r"tax\s*(?:identification|reference)?|income\s*tax|epf|kwsp|socso|perkeso)"
    r"\s*(?:no\.?|number)?\s*:\s*([A-Z0-9-]{4,40})\s*$"
)
GOVERNMENT_ID_LABEL_PATTERN = re.compile(
    r"(?i)^\s*(?:(?:synthetic\s*)?(?:ic|nric)(?:\s*/\s*(?:ic|nric))?|"
    r"identity\s*card|national\s*(?:id|registration)|passport|driver(?:'s)?\s*licen[cs]e|"
    r"student\s*id|employee\s*id|tax\s*(?:identification|reference)?|income\s*tax|"
    r"epf|kwsp|socso|perkeso)\s*(?:no\.?|number)?\s*:?\s*(.*)$"
)
GOVERNMENT_ID_VALUE_PATTERN = re.compile(
    r"(?=[A-Z0-9 ./-]{4,40}$)(?=.*\d)[A-Z0-9][A-Z0-9 ./-]{3,39}", re.I
)
INDONESIAN_NIK_LABEL_PATTERN = re.compile(r"(?i)^\s*NIK\s*:?\s*(.*)$")
INDONESIAN_NIK_VALUE_PATTERN = re.compile(r"\d{16}")
PASSPORT_MRZ_LINE_PATTERN = re.compile(r"[A-Z0-9<]{30,44}")
PHONE_LABEL_PATTERN = re.compile(
    r"(?i)^\s*(?:mobile(?:\s*number)?|phone(?:\s*number)?|telephone|telefon|"
    r"no\.?\s*telefon|nombor\s*telefon|emergency\s*contact\s*(?:phone|number)|"
    r"nombor\s*telefon\s*kecemasan)\s*:?\s*(.*)$"
)
LABELLED_PHONE_VALUE_PATTERN = re.compile(r"\+?[0-9X][0-9X ()-]{6,24}", re.I)
LABELLED_FINANCIAL_ACCOUNT_PATTERN = re.compile(
    r"(?im)^\s*(?:bank\s*)?(?:account|acct)\s*(?:no\.?|number)?\s*:\s*"
    r"([A-Z0-9 -]{6,40})\s*$"
)
DOB_LABEL_PATTERN = re.compile(
    r"(?i)^\s*(?:date\s*of\s*birth|birth\s*date|d\.?\s*o\.?\s*b\.?|"
    r"tarikh\s*(?:lahir|kelahiran)|tanggal\s*lahir)\s*:?\s*(.*)$"
)
MONTH_NAME_PATTERN = (
    r"jan(?:uary|uari)?|feb(?:ruary|ruari)?|mar(?:ch)?|mac|apr(?:il)?|may|mei|"
    r"jun(?:e)?|jul(?:y|ai)?|aug(?:ust)?|ogos|sep(?:tember)?|oktober|oct(?:ober)?|"
    r"nov(?:ember)?|disember|dec(?:ember)?"
)
DOB_VALUE_PATTERN = re.compile(
    rf"(?i)\b(?:\d{{4}}[./-]\d{{1,2}}[./-]\d{{1,2}}|"
    rf"\d{{1,2}}[./-]\d{{1,2}}[./-]\d{{2,4}}|"
    rf"\d{{1,2}}\s+(?:{MONTH_NAME_PATTERN})\s+\d{{2,4}}|"
    rf"(?:{MONTH_NAME_PATTERN})\s+\d{{1,2}},?\s+\d{{2,4}})\b"
)
MONTH_NUMBERS = {
    "jan": 1,
    "january": 1,
    "januari": 1,
    "feb": 2,
    "february": 2,
    "februari": 2,
    "mar": 3,
    "march": 3,
    "mac": 3,
    "apr": 4,
    "april": 4,
    "may": 5,
    "mei": 5,
    "jun": 6,
    "june": 6,
    "jul": 7,
    "july": 7,
    "julai": 7,
    "aug": 8,
    "august": 8,
    "ogos": 8,
    "sep": 9,
    "september": 9,
    "oct": 10,
    "october": 10,
    "oktober": 10,
    "nov": 11,
    "november": 11,
    "dec": 12,
    "december": 12,
    "disember": 12,
}
MALAYSIAN_ADDRESS_LINE_PATTERN = re.compile(
    r"(?im)^\s*([^\n]{0,80}\b(?:no\.?\s*\d+[A-Za-z]?(?:[-/]\d+)?|unit|blok|block|apartment|pangsapuri|"
    r"peti\s+surat|p\.?\s*o\.?\s*box|jalan|jln\.?|lorong|persiaran|taman|"
    r"kampung|kg\.?|lebuh|lebuhraya|simpang|seksyen|bandar)\b[^\n]{2,200})\s*$"
)
MALAYSIAN_POSTCODE_LINE_PATTERN = re.compile(
    r"(?im)^\s*([^\n]{0,120}\b\d{5}\b[^\n]{0,120}\b(?:johor|kedah|kelantan|melaka|"
    r"negeri\s+sembilan|pahang|perak|perlis|pulau\s+pinang|penang|sabah|sarawak|"
    r"selangor|terengganu|kuala\s+lumpur|putrajaya|labuan)\b[^\n]{0,80})\s*$"
)
MALAYSIAN_LOCALITY_PATTERN = re.compile(
    r"(?i)\b((?:bandar|taman|kampung|kg\.?|seksyen)\s+[A-Z0-9][A-Z0-9 .'-]{1,80}?"
    r"(?:,\s*[A-Z][A-Z .'-]{1,50})?\s*,\s*(?:johor|kedah|kelantan|melaka|"
    r"negeri\s+sembilan|pahang|perak|perlis|pulau\s+pinang|penang|sabah|sarawak|"
    r"selangor|terengganu|kuala\s+lumpur|putrajaya|labuan))\b"
)
ADDRESS_LABEL_PATTERN = re.compile(
    r"^\s*(?:address|alamat(?:\s+rumah)?)\s*:?\s*(.*)$", re.I
)
ADDRESS_SECTION_BOUNDARY_PATTERN = re.compile(
    r"^\s*(?:name|nama|nric|no\.?\s*kad|matric|faculty|fakulti|programme|program|"
    r"academic|year|tahun|sponsor|cohort|email|phone|telefon|summary|experience|"
    r"education|skills?|no\.?\s*telefon|e[- ]?mel|pekerjaan|majikan|"
    r"no\.?\s*(?:pekerja|pasport)|status\s*perkahwinan|klasifikasi\s*data)\b\s*:?.*$",
    re.I,
)
FIELD_SECTION_BOUNDARY_PATTERN = re.compile(
    r"(?i)^\s*(?:full\s*name|name|nama|synthetic\s*(?:ic|nric)|ic|nric|"
    r"date\s*of\s*birth|birth\s*date|tarikh\s*(?:lahir|kelahiran)|age|umur|"
    r"gender|jantina|nationality|warganegara|address|alamat|mobile|phone|telefon|"
    r"email|e-mel|occupation|pekerjaan|employer|majikan|employee\s*id|"
    r"emergency\s*contact|status\s*perkahwinan|data\s*classification|klasifikasi\s*data)\b"
)


def _labelled_address_blocks(text: str) -> list[str]:
    """Capture Malay/English address continuations without consuming later sections."""
    lines = str(text or "").splitlines()
    matches = []
    for index, line in enumerate(lines):
        labelled = ADDRESS_LABEL_PATTERN.match(line)
        if not labelled:
            continue
        inline = labelled.group(1).strip()
        if inline:
            matches.append(inline)
        for continuation in lines[index + 1 : index + 5]:
            value = continuation.strip()
            if not value or ADDRESS_SECTION_BOUNDARY_PATTERN.match(value):
                break
            matches.append(value)
    return list(dict.fromkeys(value for value in matches if len(value) >= 3))


def _valid_dob(value: str) -> bool:
    """Validate a labelled date as a plausible date of birth."""
    cleaned = re.sub(r"\s+", " ", value.strip().replace(",", ""))
    numeric = re.fullmatch(r"(\d{1,4})[./-](\d{1,2})[./-](\d{1,4})", cleaned)
    if numeric:
        first, second, third = (int(part) for part in numeric.groups())
        if len(numeric.group(1)) == 4:
            year, month, day = first, second, third
        else:
            day, month, year = first, second, third
    else:
        parts = cleaned.casefold().split()
        if len(parts) != 3:
            return False
        if parts[0].isdigit() and parts[1] in MONTH_NUMBERS:
            day, month, year = int(parts[0]), MONTH_NUMBERS[parts[1]], int(parts[2])
        elif parts[0] in MONTH_NUMBERS and parts[1].isdigit():
            month, day, year = MONTH_NUMBERS[parts[0]], int(parts[1]), int(parts[2])
        else:
            return False

    years = [year] if year >= 100 else [1900 + year, 2000 + year]
    today = datetime.now(UTC).date()
    for candidate_year in years:
        if not _is_valid_date(candidate_year, month, day):
            continue
        candidate = date(candidate_year, month, day)
        if candidate <= today and candidate_year >= today.year - 125:
            return True
    return False


def _labelled_date_of_birth_values(text: str) -> list[str]:
    """Capture DOB values inline or on the line following a Malay/English label."""
    lines = [line.strip() for line in str(text or "").splitlines()]
    matches = []
    for index, line in enumerate(lines):
        labelled = DOB_LABEL_PATTERN.match(line)
        if not labelled:
            continue
        candidates = [labelled.group(1), *lines[index + 1 : index + 3]]
        for candidate_line in candidates:
            candidate_match = DOB_VALUE_PATTERN.search(candidate_line)
            if candidate_match and _valid_dob(candidate_match.group(0)):
                matches.append(candidate_match.group(0))
                break
    return list(dict.fromkeys(matches))


def _labelled_field_values(text: str, label_pattern, value_pattern) -> list[str]:
    """Capture a strict field value inline or on the next line of a table-like PDF."""
    lines = [line.strip() for line in str(text or "").splitlines()]
    matches = []
    for index, line in enumerate(lines):
        labelled = label_pattern.match(line)
        if not labelled:
            continue
        candidates = [labelled.group(1), *lines[index + 1 : index + 3]]
        for candidate_index, candidate in enumerate(candidates):
            value = candidate.strip()
            if not value:
                continue
            if value_pattern.fullmatch(value):
                matches.append(value)
                break
            if candidate_index and FIELD_SECTION_BOUNDARY_PATTERN.match(value):
                break
    return list(dict.fromkeys(matches))


def _passport_mrz_values(text: str) -> list[str]:
    """Recognise passport MRZ data when a P< line or passport label is present."""
    lines = [line.strip() for line in str(text or "").splitlines()]
    has_passport_label = bool(re.search(r"\b(?:passport|pasport)\b", text, re.I))
    values = []
    for first, second in pairwise(lines):
        name_line = re.sub(r"\s+", "", first).upper()
        number_line = re.sub(r"\s+", "", second).upper()
        if (
            ((name_line.startswith("P<") and 25 <= len(name_line) <= 44) or has_passport_label)
            and PASSPORT_MRZ_LINE_PATTERN.fullmatch(number_line)
            and any(char.isdigit() for char in number_line[:15])
        ):
            values.append(second)
    return list(dict.fromkeys(values))


def _is_valid_nric(value: str) -> bool:
    """Validate the YYMMDD component instead of trusting regex shape alone."""
    compact_date = re.sub(r"\D", "", value)[:6]
    year, month, day = int(compact_date[:2]), int(compact_date[2:4]), int(compact_date[4:6])
    return any(
        _is_valid_date(century + year, month, day)
        for century in (1900, 2000)
    )


def _is_valid_date(year: int, month: int, day: int) -> bool:
    try:
        date(year, month, day)
        return True
    except ValueError:
        return False


def is_luhn_valid(cc_number: str) -> bool:
    """
    Validates a credit card number using the Luhn algorithm.
    """
    # Remove all non-digit characters
    digits = [int(c) for c in cc_number if c.isdigit()]
    if not digits:
        return False

    # Reverse the digits
    digits.reverse()

    # Double every second digit
    for i in range(1, len(digits), 2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9

    # Check if sum is divisible by 10
    return sum(digits) % 10 == 0


def _find_legacy_sensitive_patterns(text: str) -> dict:
    """
    Scans text for sensitive patterns and returns the matches.
    """
    nric_candidates = (
        MY_IC_PATTERN.findall(text)
        + MY_IC_COMPACT_PATTERN.findall(text)
        + MY_IC_SPACED_PATTERN.findall(text)
    )
    valid_nrics = list(dict.fromkeys(match for match in nric_candidates if _is_valid_nric(match)))
    labelled_government_ids = list(
        dict.fromkeys(
            [match.strip() for match in LABELLED_GOVERNMENT_ID_PATTERN.findall(text)]
            + _labelled_field_values(text, GOVERNMENT_ID_LABEL_PATTERN, GOVERNMENT_ID_VALUE_PATTERN)
            + _labelled_field_values(text, INDONESIAN_NIK_LABEL_PATTERN, INDONESIAN_NIK_VALUE_PATTERN)
            + _passport_mrz_values(text)
        )
    )
    normalized_nrics = {re.sub(r"\W", "", value).casefold() for value in valid_nrics}
    results = {
        "my_ic": valid_nrics,
        "my_phone": list(
            dict.fromkeys(
                MY_PHONE_PATTERN.findall(text)
                + _labelled_field_values(text, PHONE_LABEL_PATTERN, LABELLED_PHONE_VALUE_PATTERN)
            )
        ),
        "email": EMAIL_PATTERN.findall(text),
        "credit_card": [],
        "name": [match.strip() for match in LABELLED_NAME_PATTERN.findall(text)],
        "address": list(
            dict.fromkeys(
                _labelled_address_blocks(text)
                + [
                    match.strip()
                    for pattern in (
                        LABELLED_ADDRESS_PATTERN,
                        MALAYSIAN_ADDRESS_LINE_PATTERN,
                        MALAYSIAN_POSTCODE_LINE_PATTERN,
                        MALAYSIAN_LOCALITY_PATTERN,
                    )
                    for match in pattern.findall(text)
                ]
            )
        ),
        "matric_number": [match.strip() for match in LABELLED_MATRIC_PATTERN.findall(text)],
        "government_id": [
            value
            for value in labelled_government_ids
            if re.sub(r"\W", "", value).casefold() not in normalized_nrics
        ],
        "financial_account": [
            match.strip() for match in LABELLED_FINANCIAL_ACCOUNT_PATTERN.findall(text)
        ],
        "date_of_birth": _labelled_date_of_birth_values(text),
    }

    # Process credit cards with Luhn validation
    potential_ccs = CREDIT_CARD_PATTERN.findall(text)
    for cc in potential_ccs:
        # Clean string to pass to validator
        clean_cc = re.sub(r"[\s-]", "", cc)
        if len(clean_cc) >= 13 and len(clean_cc) <= 16 and is_luhn_valid(clean_cc):
            # Preserve the original formatting so the redaction pass can replace
            # spaces or hyphens exactly as they appeared in the source text.
            results["credit_card"].append(cc)

    return results


def discover_sensitive_data(text: str):
    """Return rich, masked findings while retaining the proven legacy detectors as seeds."""
    from src.pii_engine import PIIEngine

    return PIIEngine().scan(text, seed_matches=_find_legacy_sensitive_patterns(text))


def find_sensitive_patterns(text: str) -> dict:
    """Compatibility adapter used by the format-preserving redaction pipeline."""
    legacy = _find_legacy_sensitive_patterns(text)
    enriched = discover_sensitive_data(text).redaction_map()
    for data_type, matches in enriched.items():
        values = legacy.setdefault(data_type, [])
        for match in matches:
            if match not in values:
                values.append(match)
    return legacy


def redact_sensitive_data(text: str, results: dict) -> str:
    """
    Redacts the identified sensitive data from the original text.
    Replaces matches with [REDACTED - TYPE].
    """
    redacted_text = text
    for data_type, matches in results.items():
        for match in matches:
            if data_type in {"name", "person_name"}:
                if str(match).strip().casefold() in {
                    "name", "nama", "email", "e-mail", "phone", "telefon", "address", "alamat"
                }:
                    continue
                mask = "[REDACTED - NAME]"
            elif data_type == "my_ic":
                # Preserve last 4 digits for verification if needed, or mask entirely
                mask = "[REDACTED - NRIC]"
            elif data_type == "credit_card":
                mask = "[REDACTED - CC]"
            elif data_type == "email":
                mask = "[REDACTED - EMAIL]"
            elif data_type == "my_phone":
                mask = "[REDACTED - PHONE]"
            else:
                mask = "[REDACTED]"

            redacted_text = redacted_text.replace(match, mask)

    return redacted_text
