from modules.base import BaseModule, DorkTemplate


class FileAndDirectoryModule(BaseModule):
    name = "fileanddirectory"
    description = "File and directory discovery via Google Dorking"

    def dorks(self) -> list[DorkTemplate]:
        t = self._make_dork
        target = "{target}"

        return [

            t(f"site:{target} filetype:pdf",
              "PDF documents indexed on target",
              "document-exposure", "low", ["pdf", "documents"]),

            t(f"site:{target} filetype:doc OR filetype:docx",
              "Microsoft Word documents",
              "document-exposure", "low", ["office", "documents"]),

            t(f"site:{target} filetype:xls OR filetype:xlsx",
              "Microsoft Excel spreadsheets",
              "document-exposure", "medium", ["office", "spreadsheet"]),

            t(f"site:{target} filetype:ppt OR filetype:pptx",
              "Microsoft PowerPoint presentations",
              "document-exposure", "low", ["office", "presentation"]),

            t(f"site:{target} filetype:txt",
              "Plain-text files exposed on target",
              "document-exposure", "medium", ["plaintext"]),

            t(f"site:{target} filetype:rtf",
              "Rich Text Format documents",
              "document-exposure", "low", ["rtf", "documents"]),

            t(f"site:{target} filetype:odt OR filetype:ods OR filetype:odp",
              "OpenDocument format files",
              "document-exposure", "low", ["openoffice", "documents"]),

            t(f"site:{target} filetype:sql",
              "SQL dump files exposed",
              "database-exposure", "critical", ["sql", "database", "backup"]),

            t(f"site:{target} filetype:bak",
              "Generic backup files (.bak)",
              "database-exposure", "critical", ["backup", "database"]),

            t(f"site:{target} filetype:dump",
              "Database dump files (.dump)",
              "database-exposure", "critical", ["dump", "database"]),

            t(f"site:{target} filetype:db",
              "Raw database files (.db)",
              "database-exposure", "critical", ["database"]),

            t(f"site:{target} filetype:sqlite",
              "SQLite database files",
              "database-exposure", "critical", ["sqlite", "database"]),

            t(f"site:{target} filetype:mdb",
              "Microsoft Access database files",
              "database-exposure", "high", ["access", "database"]),

            t(f"site:{target} filetype:dbf",
              "dBASE database files",
              "database-exposure", "high", ["dbase", "database"]),

            t(f"site:{target} filetype:env",
              ".env environment configuration files",
              "config-exposure", "critical", ["env", "credentials", "config"]),

            t(f"site:{target} filetype:cfg",
              "Generic configuration files (.cfg)",
              "config-exposure", "high", ["config"]),

            t(f"site:{target} filetype:ini",
              "INI configuration files",
              "config-exposure", "high", ["config", "ini"]),

            t(f"site:{target} filetype:conf",
              "Apache/Nginx/service config files",
              "config-exposure", "high", ["config", "apache", "nginx"]),

            t(f"site:{target} filetype:config",
              "Application config files (.config)",
              "config-exposure", "high", ["config", "dotnet"]),

            t(f"site:{target} filetype:yaml OR filetype:yml",
              "YAML configuration files",
              "config-exposure", "high", ["yaml", "config", "devops"]),

            t(f"site:{target} filetype:toml",
              "TOML configuration files",
              "config-exposure", "medium", ["toml", "config"]),

            t(f"site:{target} filetype:properties",
              "Java .properties configuration files",
              "config-exposure", "high", ["java", "config", "properties"]),

            t(f"site:{target} filetype:xml inurl:config",
              "XML configuration files",
              "config-exposure", "high", ["xml", "config"]),

            t(f"site:{target} filetype:log",
              "Log files exposed on target",
              "log-exposure", "high", ["log"]),

            t(f"site:{target} filetype:log intext:\"error\"",
              "Log files containing error messages",
              "log-exposure", "high", ["log", "error"]),

            t(f"site:{target} filetype:log intext:\"exception\"",
              "Log files containing exception traces",
              "log-exposure", "high", ["log", "exception", "stacktrace"]),

            t(f"site:{target} filetype:log intext:\"warning\"",
              "Log files with warning entries",
              "log-exposure", "medium", ["log", "warning"]),

            t(f"site:{target} filetype:log intext:\"stack trace\"",
              "Log files with stack traces — reveals internal paths and frameworks",
              "log-exposure", "high", ["log", "stacktrace"]),

            t(f"site:{target} filetype:log intext:\"SQL\"",
              "Log files with SQL statements",
              "log-exposure", "critical", ["log", "sql", "database"]),

            t(f"site:{target} filetype:log intext:\"password\"",
              "Log files containing the word 'password'",
              "log-exposure", "critical", ["log", "credentials"]),

            t(f"site:{target} filetype:log intext:\"username\"",
              "Log files containing usernames",
              "log-exposure", "high", ["log", "credentials"]),

            t(f"site:{target} filetype:log intext:\"token\"",
              "Log files containing token references",
              "log-exposure", "high", ["log", "token"]),

            t(f"site:{target} filetype:zip",
              "ZIP archive files exposed",
              "archive-exposure", "high", ["archive", "zip"]),

            t(f"site:{target} filetype:tar",
              "TAR archive files exposed",
              "archive-exposure", "high", ["archive", "tar"]),

            t(f"site:{target} filetype:gz OR filetype:tgz",
              "GZIP compressed archives",
              "archive-exposure", "high", ["archive", "gzip"]),

            t(f"site:{target} filetype:rar",
              "RAR archive files",
              "archive-exposure", "high", ["archive", "rar"]),

            t(f"site:{target} filetype:7z",
              "7-Zip archive files",
              "archive-exposure", "high", ["archive", "7zip"]),

            t(f"site:{target} inurl:backup",
              "URLs containing 'backup' path segment",
              "backup-exposure", "high", ["backup"]),

            t(f"site:{target} inurl:old",
              "URLs containing 'old' — may be outdated copies",
              "backup-exposure", "medium", ["old", "backup"]),

            t(f"site:{target} inurl:archive",
              "URLs containing 'archive' path segment",
              "backup-exposure", "medium", ["archive"]),

            t(f"site:{target} inurl:_backup",
              "URLs with underscore-prefixed backup directories",
              "backup-exposure", "high", ["backup"]),

            t(f"site:{target} inurl:.bak",
              "URLs directly referencing .bak files",
              "backup-exposure", "critical", ["backup", "bak"]),

            t(f"site:{target} inurl:copy",
              "URLs containing 'copy' — may be file duplicates",
              "backup-exposure", "medium", ["copy", "backup"]),

            t(f"site:{target} inurl:temp OR inurl:tmp",
              "Temporary file or directory exposure",
              "backup-exposure", "high", ["temp", "tmp"]),

            t(f"site:{target} intitle:\"index of\"",
              "Open directory listings — general",
              "directory-listing", "high", ["directory-listing"]),

            t(f"site:{target} intitle:\"index of\" \"parent directory\"",
              "Directory listing with parent navigation enabled",
              "directory-listing", "high", ["directory-listing"]),

            t(f"site:{target} intitle:\"index of\" intext:\".sql\"",
              "Open directory listing containing SQL files",
              "directory-listing", "critical", ["directory-listing", "sql"]),

            t(f"site:{target} intitle:\"index of\" intext:\".log\"",
              "Open directory containing log files",
              "directory-listing", "high", ["directory-listing", "log"]),

            t(f"site:{target} intitle:\"index of\" intext:\".env\"",
              "Open directory with .env files visible",
              "directory-listing", "critical", ["directory-listing", "env"]),

            t(f"site:{target} intitle:\"index of\" intext:\".git\"",
              "Open directory exposing .git repository",
              "directory-listing", "critical", ["directory-listing", "git"]),

            t(f"site:{target} intitle:\"index of\" intext:\"backup\"",
              "Open directory listing with backup files",
              "directory-listing", "high", ["directory-listing", "backup"]),

            t(f"site:{target} intitle:\"index of\" intext:\"passwd\"",
              "Open directory listing containing passwd files",
              "directory-listing", "critical", ["directory-listing", "credentials"]),

            t(f"site:{target} intitle:\"index of\" \"/uploads\"",
              "User upload directory is publicly listed",
              "directory-listing", "high", ["directory-listing", "upload"]),

            t(f"site:{target} intitle:\"index of\" \"/private\"",
              "Private directory exposed via open listing",
              "directory-listing", "critical", ["directory-listing", "private"]),

            t(f"site:{target} intitle:\"index of\" \"/admin\"",
              "Admin directory open listing",
              "directory-listing", "critical", ["directory-listing", "admin"]),

            t(f"site:{target} intitle:\"index of\" \"/secret\"",
              "Secret directory exposed via open listing",
              "directory-listing", "critical", ["directory-listing", "secret"]),

            t(f"site:{target} intitle:\"index of\" \".ssh\"",
              "SSH directory exposed in open listing",
              "directory-listing", "critical", ["directory-listing", "ssh"]),

            t(f"site:{target} intitle:\"index of\" \".aws\"",
              "AWS credentials directory exposed",
              "directory-listing", "critical", ["directory-listing", "aws", "cloud"]),

            t(f"site:{target} inurl:\".git/config\"",
              "Git config file directly accessible",
              "source-exposure", "critical", ["git", "vcs", "credentials"]),

            t(f"site:{target} inurl:\".svn/entries\"",
              "SVN repository entries file exposed",
              "source-exposure", "critical", ["svn", "vcs"]),

            t(f"site:{target} inurl:\".DS_Store\"",
              ".DS_Store macOS metadata leaks directory structure",
              "source-exposure", "medium", ["macos", "metadata"]),

            t(f"site:{target} inurl:\"WEB-INF/web.xml\"",
              "Java WEB-INF configuration exposed",
              "source-exposure", "critical", ["java", "j2ee", "config"]),

            t(f"site:{target} filetype:php intext:\"mysql_connect\"",
              "PHP source exposing MySQL connection calls",
              "source-exposure", "critical", ["php", "mysql", "source"]),

            t(f"site:{target} filetype:php intext:\"$_GET\" OR intext:\"$_POST\"",
              "PHP files with superglobal references — potential injection points",
              "source-exposure", "high", ["php", "source", "injection"]),

            t(f"site:{target} filetype:asp OR filetype:aspx",
              "ASP/ASPX source or compiled pages exposed",
              "source-exposure", "medium", ["aspnet", "source"]),

            t(f"site:{target} filetype:py intext:\"import\"",
              "Python source files exposed on server",
              "source-exposure", "high", ["python", "source"]),

            t(f"site:{target} filetype:rb intext:\"ActiveRecord\"",
              "Ruby on Rails source files exposed",
              "source-exposure", "high", ["ruby", "rails", "source"]),

            t(f"site:{target} filetype:java intext:\"public static void\"",
              "Java source files directly served",
              "source-exposure", "high", ["java", "source"]),

            t(f"site:{target} filetype:js intext:\"api_key\" OR intext:\"apiKey\"",
              "JavaScript files containing API key references",
              "source-exposure", "critical", ["javascript", "api-key", "credentials"]),

            t(f"site:{target} filetype:sh intext:\"#!/bin/bash\"",
              "Bash scripts exposed on web server",
              "source-exposure", "high", ["bash", "shell", "source"]),

            t(f"site:{target} filetype:pdf intext:\"internal use only\"",
              "PDFs marked as internal — should not be public",
              "sensitive-document", "high", ["pdf", "internal", "confidential"]),

            t(f"site:{target} filetype:docx intext:\"confidential\"",
              "Word documents marked confidential",
              "sensitive-document", "high", ["docx", "confidential"]),

            t(f"site:{target} filetype:xlsx intext:\"do not distribute\"",
              "Spreadsheets with distribution restriction notices",
              "sensitive-document", "high", ["xlsx", "confidential"]),

            t(f"site:{target} filetype:pptx intext:\"draft\"",
              "Draft presentations exposed publicly",
              "sensitive-document", "medium", ["pptx", "draft"]),

            t(f"site:{target} filetype:pdf intext:\"not for public release\"",
              "PDFs explicitly marked not for public release",
              "sensitive-document", "critical", ["pdf", "confidential"]),

            t(f"site:{target} filetype:pdf intext:\"proprietary\"",
              "PDFs containing proprietary content warnings",
              "sensitive-document", "high", ["pdf", "proprietary"]),

            t(f"site:{target} ext:xlsx OR ext:csv intext:\"password\" OR intext:\"username\"",
              "Spreadsheets containing credential column headers",
              "credential-exposure", "critical", ["spreadsheet", "credentials"]),

            t(f"site:{target} inurl:\"/wp-content/uploads\" filetype:sql",
              "WordPress upload directory containing SQL files",
              "cms-exposure", "critical", ["wordpress", "sql", "upload"]),

            t(f"site:{target} inurl:\"/wp-content/backup\"",
              "WordPress backup directory exposed",
              "cms-exposure", "critical", ["wordpress", "backup"]),

            t(f"site:{target} inurl:\"wp-config.php.bak\" OR inurl:\"wp-config.php~\"",
              "WordPress configuration backup file accessible",
              "cms-exposure", "critical", ["wordpress", "config", "credentials"]),

            t(f"site:{target} filetype:json inurl:\"package\"",
              "package.json exposed — reveals dependencies and scripts",
              "source-exposure", "medium", ["nodejs", "npm", "dependencies"]),

            t(f"site:{target} filetype:json inurl:\"composer\"",
              "composer.json exposed — PHP dependency file",
              "source-exposure", "medium", ["php", "composer", "dependencies"]),

            t(f"site:{target} filetype:lock inurl:\"package-lock\" OR inurl:\"yarn.lock\"",
              "Lockfiles revealing exact dependency versions",
              "source-exposure", "low", ["nodejs", "npm", "dependencies"]),

            t(f"site:{target} inurl:\"Dockerfile\" OR inurl:\"docker-compose.yml\"",
              "Docker configuration files exposed",
              "config-exposure", "high", ["docker", "config", "devops"]),

            t(f"site:{target} filetype:tf OR filetype:tfvars",
              "Terraform infrastructure-as-code files exposed",
              "config-exposure", "critical", ["terraform", "iac", "cloud", "credentials"]),

            t(f"site:{target} inurl:\".github/workflows\" filetype:yml",
              "GitHub Actions CI/CD workflow files exposed",
              "config-exposure", "medium", ["github", "cicd", "devops"]),

            t(f"site:{target} filetype:pem OR filetype:key inurl:private",
              "Private key material in PEM or .key files",
              "crypto-exposure", "critical", ["ssl", "private-key", "credentials"]),

            t(f"site:{target} intext:\"BEGIN RSA PRIVATE KEY\"",
              "RSA private key material leaked in a document or page",
              "crypto-exposure", "critical", ["rsa", "private-key", "credentials"]),

            t(f"site:{target} intext:\"BEGIN OPENSSH PRIVATE KEY\"",
              "OpenSSH private key leaked",
              "crypto-exposure", "critical", ["ssh", "private-key", "credentials"]),

        ]