from modules.base import BaseModule, DorkTemplate


class SensDataModule(BaseModule):
    name = "sensdata"
    description = "Sensitive data and OSINT discovery via Google Dorking"

    def dorks(self) -> list[DorkTemplate]:
        t = self._make_dork
        target = "{target}"

        return [

            t(f"site:{target} filetype:xls OR filetype:xlsx intext:\"ssn\"",
              "Spreadsheets containing Social Security Number references",
              "pii-exposure", "critical", ["pii", "ssn", "spreadsheet"]),

            t(f"site:{target} filetype:xls OR filetype:xlsx intext:\"date of birth\"",
              "Spreadsheets with date of birth fields",
              "pii-exposure", "critical", ["pii", "dob", "spreadsheet"]),

            t(f"site:{target} filetype:csv intext:\"email\" intext:\"phone\"",
              "CSV files with email and phone columns — user data leak",
              "pii-exposure", "critical", ["pii", "email", "phone", "csv"]),

            t(f"site:{target} filetype:csv intext:\"first_name\" intext:\"last_name\"",
              "CSV files with full name columns",
              "pii-exposure", "critical", ["pii", "name", "csv"]),

            t(f"site:{target} filetype:xlsx intext:\"address\" intext:\"zip\"",
              "Spreadsheets with address and zip code data",
              "pii-exposure", "high", ["pii", "address", "spreadsheet"]),

            t(f"site:{target} filetype:pdf intext:\"social security\"",
              "PDFs referencing Social Security information",
              "pii-exposure", "critical", ["pii", "ssn", "pdf"]),

            t(f"site:{target} filetype:pdf intext:\"date of birth\" intext:\"passport\"",
              "PDFs with passport and date of birth — identity document data",
              "pii-exposure", "critical", ["pii", "passport", "pdf"]),

            t(f"site:{target} filetype:xls intext:\"credit card\" OR intext:\"card number\"",
              "Spreadsheets with credit card number columns",
              "pci-exposure", "critical", ["pii", "credit-card", "pci"]),

            t(f"site:{target} filetype:csv intext:\"cvv\" OR intext:\"expiry\"",
              "CSV files with CVV or card expiry data — PCI violation",
              "pci-exposure", "critical", ["pii", "credit-card", "pci"]),

            t(f"site:{target} intext:\"4[0-9]{{12}}(?:[0-9]{{3}})?\"",
              "Pages containing Visa-format card number patterns",
              "pci-exposure", "critical", ["pii", "credit-card", "pci"]),

            t(f"site:{target} filetype:pdf intext:\"invoice\" intext:\"bank account\"",
              "Invoice PDFs containing bank account information",
              "financial-exposure", "critical", ["financial", "bank", "invoice"]),

            t(f"site:{target} filetype:xls intext:\"IBAN\" OR intext:\"SWIFT\"",
              "Spreadsheets with IBAN or SWIFT banking codes",
              "financial-exposure", "critical", ["financial", "iban", "swift"]),

            t(f"site:{target} filetype:pdf intext:\"balance\" intext:\"account number\"",
              "Financial statements with account numbers",
              "financial-exposure", "critical", ["financial", "account"]),

            t(f"site:{target} filetype:xls OR filetype:csv intext:\"salary\"",
              "Spreadsheets containing salary information",
              "financial-exposure", "high", ["financial", "salary", "hr"]),

            t(f"site:{target} filetype:pdf intext:\"payroll\"",
              "Payroll documents exposed publicly",
              "financial-exposure", "critical", ["financial", "payroll", "hr"]),

            t(f"site:{target} filetype:xls OR filetype:xlsx intext:\"payroll\"",
              "Payroll spreadsheets exposed",
              "financial-exposure", "critical", ["financial", "payroll", "hr"]),

            t(f"site:{target} filetype:pdf intitle:\"medical\" OR intitle:\"patient\"",
              "Medical or patient PDFs exposed",
              "healthcare-exposure", "critical", ["hipaa", "medical", "patient"]),

            t(f"site:{target} filetype:xls intext:\"diagnosis\" OR intext:\"treatment\"",
              "Spreadsheets with medical diagnosis or treatment data",
              "healthcare-exposure", "critical", ["hipaa", "medical", "pii"]),

            t(f"site:{target} filetype:pdf intext:\"prescription\"",
              "Prescription documents accessible publicly",
              "healthcare-exposure", "critical", ["hipaa", "medical", "prescription"]),

            t(f"site:{target} filetype:csv intext:\"patient_id\" OR intext:\"patient id\"",
              "CSV files with patient identifier columns",
              "healthcare-exposure", "critical", ["hipaa", "patient", "pii"]),

            t(f"site:{target} filetype:pdf intext:\"NDA\" OR intitle:\"Non-Disclosure\"",
              "NDA documents publicly accessible",
              "legal-exposure", "high", ["legal", "nda", "confidential"]),

            t(f"site:{target} filetype:pdf intitle:\"contract\" intext:\"confidential\"",
              "Confidential contract PDFs exposed",
              "legal-exposure", "high", ["legal", "contract", "confidential"]),

            t(f"site:{target} filetype:docx intext:\"attorney-client privilege\"",
              "Privileged legal documents exposed",
              "legal-exposure", "critical", ["legal", "privilege", "confidential"]),

            t(f"site:{target} filetype:pdf intext:\"settlement\" intext:\"agreement\"",
              "Settlement agreement documents exposed",
              "legal-exposure", "high", ["legal", "settlement"]),

            t(f"site:{target} filetype:pdf intitle:\"M&A\" OR intitle:\"merger\"",
              "M&A or merger documents exposed — sensitive financial intelligence",
              "legal-exposure", "critical", ["legal", "financial", "ma"]),

            t(f"site:{target} filetype:xls OR filetype:csv intext:\"employee\"",
              "Employee data spreadsheets",
              "hr-exposure", "high", ["hr", "employee", "pii"]),

            t(f"site:{target} filetype:xls intext:\"performance review\"",
              "Employee performance review spreadsheets",
              "hr-exposure", "high", ["hr", "employee", "confidential"]),

            t(f"site:{target} filetype:pdf intext:\"resume\" OR intitle:\"curriculum vitae\"",
              "Employee resumes or CVs publicly accessible",
              "hr-exposure", "medium", ["hr", "pii", "resume"]),

            t(f"site:{target} filetype:xls OR filetype:xlsx intext:\"hire date\"",
              "Spreadsheets with employee hire date data",
              "hr-exposure", "medium", ["hr", "employee"]),

            t(f"site:{target} filetype:pdf intext:\"disciplinary\" OR intext:\"termination\"",
              "HR disciplinary or termination documents exposed",
              "hr-exposure", "critical", ["hr", "employee", "confidential"]),

            t(f"site:{target} inurl:\"backup\" filetype:sql",
              "SQL backup files accessible — full database dump risk",
              "database-exposure", "critical", ["database", "backup", "sql"]),

            t(f"site:{target} filetype:sql intext:\"CREATE TABLE users\"",
              "SQL dumps containing users table definition",
              "database-exposure", "critical", ["database", "sql", "users"]),

            t(f"site:{target} filetype:sql intext:\"INSERT INTO users\"",
              "SQL dumps with user record INSERT statements",
              "database-exposure", "critical", ["database", "sql", "users"]),

            t(f"site:{target} filetype:sql intext:\"INSERT INTO customers\"",
              "SQL dumps with customer record INSERT statements",
              "database-exposure", "critical", ["database", "sql", "customers"]),

            t(f"site:{target} filetype:sql intext:\"INSERT INTO orders\"",
              "SQL dumps with order data — may include payment and PII",
              "database-exposure", "critical", ["database", "sql", "orders", "pii"]),

            t(f"site:{target} intitle:\"Index of\" intext:\".sql\"",
              "Directory listing exposing SQL files",
              "database-exposure", "critical", ["database", "sql", "directory-listing"]),

            t(f"site:{target} filetype:csv intext:\"username\" intext:\"hash\"",
              "CSV files with username and password hash columns",
              "credential-exposure", "critical", ["credentials", "hash", "csv"]),

            t(f"site:{target} filetype:txt intext:\"username\" intext:\"password\"",
              "Text files containing plaintext username and password pairs",
              "credential-exposure", "critical", ["credentials", "plaintext", "txt"]),

            t(f"site:{target} intext:\"BEGIN PGP MESSAGE\"",
              "PGP-encrypted message blocks in page or file content",
              "crypto-exposure", "medium", ["pgp", "crypto"]),

            t(f"site:{target} filetype:asc OR filetype:gpg",
              "GPG/PGP key or message files exposed",
              "crypto-exposure", "medium", ["gpg", "pgp", "crypto"]),

            t(f"site:{target} filetype:pdf intext:\"audit report\"",
              "Audit report PDFs exposed — reveals compliance posture",
              "compliance-exposure", "high", ["audit", "compliance", "confidential"]),

            t(f"site:{target} filetype:pdf intext:\"penetration test\" OR intitle:\"pentest\"",
              "Penetration test reports publicly accessible",
              "compliance-exposure", "critical", ["pentest", "security-report"]),

            t(f"site:{target} filetype:pdf intitle:\"vulnerability assessment\"",
              "Vulnerability assessment reports exposed",
              "compliance-exposure", "critical", ["vulnerability", "security-report"]),

            t(f"site:{target} filetype:pdf intext:\"SOC 2\" OR intext:\"SOC2\"",
              "SOC 2 compliance reports publicly accessible",
              "compliance-exposure", "high", ["soc2", "compliance"]),

            t(f"site:{target} filetype:pdf intext:\"ISO 27001\" intext:\"audit\"",
              "ISO 27001 audit documents exposed",
              "compliance-exposure", "high", ["iso27001", "compliance"]),

            t(f"site:{target} filetype:pdf intext:\"GDPR\" intext:\"data processing\"",
              "GDPR data processing documentation exposed",
              "compliance-exposure", "medium", ["gdpr", "compliance", "privacy"]),

            t(f"site:{target} intext:\"internal use only\" filetype:pdf",
              "PDFs marked internal-use-only accessible publicly",
              "sensitive-document", "high", ["internal", "confidential"]),

            t(f"site:{target} intext:\"do not share\" filetype:pdf",
              "Documents marked do-not-share exposed publicly",
              "sensitive-document", "high", ["confidential"]),

            t(f"site:{target} intext:\"classified\" filetype:pdf",
              "PDFs with classified designation",
              "sensitive-document", "critical", ["classified", "confidential"]),

            t(f"site:{target} intext:\"strictly confidential\" filetype:pdf",
              "PDFs marked strictly confidential",
              "sensitive-document", "critical", ["confidential"]),

            t(f"site:{target} intext:\"trade secret\"",
              "Pages or documents referencing trade secrets",
              "sensitive-document", "critical", ["trade-secret", "legal", "ip"]),

            t(f"site:{target} filetype:pdf intext:\"board minutes\" OR intitle:\"board of directors\"",
              "Board meeting minutes exposed — strategic intelligence",
              "sensitive-document", "critical", ["board", "confidential", "strategic"]),

            t(f"site:{target} filetype:xls OR filetype:xlsx intext:\"strategic plan\"",
              "Strategic planning spreadsheets exposed",
              "sensitive-document", "high", ["strategic", "confidential"]),

            t(f"site:{target} filetype:pptx intext:\"roadmap\" intext:\"confidential\"",
              "Confidential product roadmap presentations",
              "sensitive-document", "high", ["roadmap", "confidential", "strategic"]),

        ]