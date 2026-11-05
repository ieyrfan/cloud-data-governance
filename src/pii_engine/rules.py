from __future__ import annotations

CONTEXT_LABELS = {
    "MALAYSIA_NRIC": (
        "ic", "i/c", "nric", "mykad", "kad pengenalan", "no kad pengenalan", "no k/p",
        "identity number", "identity card",
    ),
    "PHONE_NUMBER": (
        "phone", "telephone", "mobile", "tel", "contact", "whatsapp", "telefon",
        "nombor telefon", "no telefon",
    ),
    "EMAIL_ADDRESS": ("email", "e-mail", "e-mel", "mail"),
    "DATE_OF_BIRTH": (
        "dob", "d.o.b", "date of birth", "birth date", "born", "tarikh lahir",
        "tarikh kelahiran", "tanggal lahir",
    ),
    "PERSON_NAME": ("name", "full name", "nama", "customer name", "patient name", "student name"),
    "POSTAL_ADDRESS": (
        "address", "home address", "residential address", "mailing address", "alamat",
    ),
    "EMPLOYEE_ID": (
        "employee id", "employee no", "employee number", "emp id", "staff id", "staff no",
        "staff number", "personnel id", "personnel number", "no pekerja", "no kakitangan",
        "no staf", "worker id", "payroll number",
    ),
    "STUDENT_ID": (
        "student id", "student number", "matric", "matric number", "matriculation number",
        "no matrik", "candidate number", "university id",
    ),
    "PASSPORT_NUMBER": (
        "passport", "pasport", "passport no", "passport number", "no passport", "no pasport",
        "no. pasport",
        "travel document",
    ),
    "FINANCIAL_ACCOUNT": (
        "bank account", "account number", "account no", "akaun bank", "nombor akaun",
        "iban", "swift", "bic",
    ),
    "PATIENT_ID": ("patient id", "patient number", "medical record", "mrn"),
    "CUSTOMER_ID": ("customer id", "customer number", "member id", "policy number"),
    "USER_IDENTIFIER": ("user id", "userid", "username", "account handle", "login"),
}

NEGATIVE_DATE_CONTEXT = (
    "created_at", "updated_at", "transaction_date", "log_date", "timestamp", "invoice_date",
    "report date", "tarikh laporan",
)

SEVERITY = {
    "MALAYSIA_NRIC": "CRITICAL",
    "GENERIC_NATIONAL_ID": "CRITICAL",
    "PASSPORT_NUMBER": "CRITICAL",
    "PAYMENT_CARD": "CRITICAL",
    "SECRET": "CRITICAL",
    "PRIVATE_KEY": "CRITICAL",
    "AWS_ACCESS_KEY": "CRITICAL",
    "FINANCIAL_ACCOUNT": "HIGH",
    "POSTAL_ADDRESS": "HIGH",
    "DATE_OF_BIRTH": "HIGH",
    "GPS_COORDINATES": "HIGH",
    "PATIENT_ID": "HIGH",
    "PHONE_NUMBER": "MEDIUM",
    "EMAIL_ADDRESS": "MEDIUM",
    "EMPLOYEE_ID": "MEDIUM",
    "STUDENT_ID": "MEDIUM",
    "CUSTOMER_ID": "MEDIUM",
    "DRIVING_LICENCE": "HIGH",
    "VISA_NUMBER": "HIGH",
    "RESIDENCE_PERMIT": "HIGH",
    "TAX_ID": "HIGH",
    "PERSON_NAME": "MEDIUM",
    "USER_IDENTIFIER": "MEDIUM",
    "IP_ADDRESS": "LOW",
    "MAC_ADDRESS": "LOW",
}

CATEGORY = {
    "MALAYSIA_NRIC": "IDENTITY",
    "GENERIC_NATIONAL_ID": "IDENTITY",
    "PASSPORT_NUMBER": "IDENTITY",
    "DRIVING_LICENCE": "IDENTITY",
    "VISA_NUMBER": "IDENTITY",
    "RESIDENCE_PERMIT": "IDENTITY",
    "TAX_ID": "IDENTITY",
    "PERSON_NAME": "IDENTITY",
    "PHONE_NUMBER": "CONTACT",
    "EMAIL_ADDRESS": "CONTACT",
    "POSTAL_ADDRESS": "LOCATION",
    "GPS_COORDINATES": "LOCATION",
    "DATE_OF_BIRTH": "PERSONAL",
    "PAYMENT_CARD": "FINANCIAL",
    "FINANCIAL_ACCOUNT": "FINANCIAL",
    "EMPLOYEE_ID": "EMPLOYMENT",
    "STUDENT_ID": "EDUCATION",
    "PATIENT_ID": "HEALTH",
    "CUSTOMER_ID": "IDENTIFIER",
    "USER_IDENTIFIER": "DIGITAL_IDENTIFIER",
    "IP_ADDRESS": "NETWORK",
    "MAC_ADDRESS": "NETWORK",
    "SECRET": "SECRET",
    "PRIVATE_KEY": "SECRET",
    "AWS_ACCESS_KEY": "CREDENTIAL",
}
