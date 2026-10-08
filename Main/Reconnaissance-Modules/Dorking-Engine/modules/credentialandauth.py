from modules.base import BaseModule, DorkTemplate


class CredentialAndAuthModule(BaseModule):
    name = "credentialandauth"
    description = "Credentials and authentication discovery via Google Dorking"

    def dorks(self) -> list[DorkTemplate]:
        t = self._make_dork
        target = "{target}"

        return [

            t(f"site:{target} inurl:admin",
              "Admin panel URLs",
              "login-panel", "high", ["admin", "panel"]),

            t(f"site:{target} inurl:login",
              "Login page discovery",
              "login-panel", "medium", ["login"]),

            t(f"site:{target} inurl:signin",
              "Sign-in page discovery",
              "login-panel", "medium", ["signin"]),

            t(f"site:{target} inurl:portal",
              "Portal login pages",
              "login-panel", "medium", ["portal"]),

            t(f"site:{target} inurl:dashboard",
              "Dashboard URLs — may be accessible without auth",
              "login-panel", "high", ["dashboard"]),

            t(f"site:{target} inurl:controlpanel",
              "Control panel interfaces",
              "login-panel", "high", ["controlpanel"]),

            t(f"site:{target} inurl:cpanel",
              "cPanel hosting control panel",
              "login-panel", "high", ["cpanel", "hosting"]),

            t(f"site:{target} inurl:webmail",
              "Webmail login interfaces",
              "login-panel", "medium", ["webmail", "email"]),

            t(f"site:{target} inurl:manage",
              "Management interface URLs",
              "login-panel", "high", ["manage"]),

            t(f"site:{target} inurl:backend",
              "Backend admin interface",
              "login-panel", "high", ["backend"]),

            t(f"site:{target} inurl:staff",
              "Staff portal or login",
              "login-panel", "high", ["staff"]),

            t(f"site:{target} inurl:secure",
              "Secure section of the site",
              "login-panel", "medium", ["secure"]),

            t(f"site:{target} intitle:\"admin login\"",
              "Pages titled 'admin login'",
              "login-panel", "high", ["admin", "login"]),

            t(f"site:{target} intitle:\"login\" intext:\"username\"",
              "Login pages with username field reference",
              "login-panel", "medium", ["login", "username"]),

            t(f"site:{target} intitle:\"login\" intext:\"password\"",
              "Login pages with password field reference",
              "login-panel", "medium", ["login", "password"]),

            t(f"site:{target} inurl:wp-login.php",
              "WordPress login page",
              "cms-auth", "high", ["wordpress", "login"]),

            t(f"site:{target} inurl:wp-admin",
              "WordPress admin dashboard",
              "cms-auth", "high", ["wordpress", "admin"]),

            t(f"site:{target} inurl:administrator",
              "Joomla administrator panel",
              "cms-auth", "high", ["joomla", "admin"]),

            t(f"site:{target} inurl:/user/login",
              "Drupal user login endpoint",
              "cms-auth", "high", ["drupal", "login"]),

            t(f"site:{target} inurl:typo3",
              "TYPO3 CMS backend",
              "cms-auth", "high", ["typo3", "cms"]),

            t(f"site:{target} inurl:Sitefinity/login",
              "Sitefinity CMS login panel",
              "cms-auth", "high", ["sitefinity", "cms"]),

            t(f"site:{target} inurl:umbraco",
              "Umbraco CMS backend login",
              "cms-auth", "high", ["umbraco", "cms"]),

            t(f"site:{target} inurl:craft/login OR inurl:craftcms",
              "Craft CMS admin login",
              "cms-auth", "high", ["craftcms"]),

            t(f"site:{target} inurl:expressionengine OR inurl:ee-login",
              "ExpressionEngine CMS login",
              "cms-auth", "high", ["expressionengine", "cms"]),

            t(f"site:{target} filetype:txt intext:\"password\"",
              "Plain-text files containing password references",
              "plaintext-credential", "critical", ["password", "plaintext"]),

            t(f"site:{target} filetype:txt intext:\"username\"",
              "Plain-text files containing username references",
              "plaintext-credential", "high", ["username", "plaintext"]),

            t(f"site:{target} filetype:log intext:\"password\"",
              "Log files with password references",
              "plaintext-credential", "critical", ["password", "log"]),

            t(f"site:{target} filetype:csv intext:\"password\"",
              "CSV files containing password column",
              "plaintext-credential", "critical", ["password", "csv"]),

            t(f"site:{target} filetype:xlsx intext:\"password\"",
              "Excel spreadsheets containing password data",
              "plaintext-credential", "critical", ["password", "xlsx"]),

            t(f"site:{target} filetype:sql intext:\"INSERT INTO\" intext:\"password\"",
              "SQL dumps with INSERT statements containing passwords",
              "plaintext-credential", "critical", ["password", "sql", "database"]),

            t(f"site:{target} filetype:sql intext:\"users\" intext:\"admin\"",
              "SQL dumps referencing users and admin accounts",
              "plaintext-credential", "critical", ["sql", "users", "admin"]),

            t(f"site:{target} intext:\"password=\" filetype:log",
              "Log files with password= assignment pattern",
              "plaintext-credential", "critical", ["password", "log"]),

            t(f"site:{target} intext:\"pwd=\" filetype:conf",
              "Config files with pwd= shorthand pattern",
              "plaintext-credential", "critical", ["password", "config"]),

            t(f"site:{target} intext:\"DB_PASSWORD\" filetype:env",
              ".env files exposing DB_PASSWORD variable",
              "plaintext-credential", "critical", ["database", "password", "env"]),

            t(f"site:{target} intext:\"DB_USER\" filetype:env",
              ".env files exposing DB_USER variable",
              "plaintext-credential", "critical", ["database", "username", "env"]),

            t(f"site:{target} intext:\"MAIL_PASSWORD\" filetype:env",
              ".env files exposing email service password",
              "plaintext-credential", "critical", ["email", "password", "env"]),

            t(f"site:{target} intext:\"SECRET_KEY\" filetype:env",
              ".env files with application SECRET_KEY",
              "plaintext-credential", "critical", ["secret", "env", "crypto"]),

            t(f"site:{target} intext:\"APP_KEY\" filetype:env",
              ".env files with Laravel or framework APP_KEY",
              "plaintext-credential", "critical", ["secret", "laravel", "env"]),

            t(f"site:{target} intext:\"api_key\"",
              "Pages containing api_key references",
              "api-credential", "critical", ["api-key"]),

            t(f"site:{target} intext:\"api_secret\"",
              "Pages containing api_secret references",
              "api-credential", "critical", ["api-secret"]),

            t(f"site:{target} intext:\"apiKey\"",
              "JavaScript-style apiKey camelCase references",
              "api-credential", "critical", ["api-key", "javascript"]),

            t(f"site:{target} intext:\"access_token\"",
              "OAuth or bearer access token exposure",
              "api-credential", "critical", ["token", "oauth"]),

            t(f"site:{target} intext:\"auth_token\"",
              "Authentication token exposure",
              "api-credential", "critical", ["token", "auth"]),

            t(f"site:{target} intext:\"client_secret\"",
              "OAuth client secret exposure",
              "api-credential", "critical", ["oauth", "client-secret"]),

            t(f"site:{target} intext:\"AWS_SECRET_ACCESS_KEY\"",
              "AWS secret access key leaked",
              "cloud-credential", "critical", ["aws", "cloud", "credentials"]),

            t(f"site:{target} intext:\"AWS_ACCESS_KEY_ID\"",
              "AWS access key ID leaked",
              "cloud-credential", "critical", ["aws", "cloud", "credentials"]),

            t(f"site:{target} intext:\"STRIPE_SECRET_KEY\"",
              "Stripe payment secret key exposed",
              "api-credential", "critical", ["stripe", "payment", "api-key"]),

            t(f"site:{target} intext:\"STRIPE_PUBLISHABLE_KEY\"",
              "Stripe publishable key exposed",
              "api-credential", "medium", ["stripe", "payment"]),

            t(f"site:{target} intext:\"SENDGRID_API_KEY\"",
              "SendGrid email API key exposed",
              "api-credential", "critical", ["sendgrid", "email", "api-key"]),

            t(f"site:{target} intext:\"TWILIO_AUTH_TOKEN\"",
              "Twilio authentication token exposed",
              "api-credential", "critical", ["twilio", "sms", "api-key"]),

            t(f"site:{target} intext:\"MAILGUN_API_KEY\"",
              "Mailgun API key exposed",
              "api-credential", "critical", ["mailgun", "email", "api-key"]),

            t(f"site:{target} intext:\"PAYPAL_SECRET\"",
              "PayPal secret credential exposed",
              "api-credential", "critical", ["paypal", "payment"]),

            t(f"site:{target} intext:\"GOOGLE_API_KEY\"",
              "Google API key exposed",
              "api-credential", "critical", ["google", "api-key"]),

            t(f"site:{target} intext:\"FIREBASE_API_KEY\"",
              "Firebase API key exposed",
              "api-credential", "critical", ["firebase", "google", "api-key"]),

            t(f"site:{target} filetype:js intext:\"Bearer\"",
              "JavaScript files with Bearer token patterns",
              "api-credential", "critical", ["bearer", "token", "javascript"]),

            t(f"site:{target} filetype:js intext:\"Authorization\"",
              "JavaScript files with Authorization header patterns",
              "api-credential", "high", ["authorization", "header", "javascript"]),

            t(f"site:github.com \"{target}\" \"password\"",
              "GitHub repositories leaking target passwords",
              "vcs-credential", "critical", ["github", "password"]),

            t(f"site:github.com \"{target}\" \"api_key\"",
              "GitHub repositories with target API keys",
              "vcs-credential", "critical", ["github", "api-key"]),

            t(f"site:github.com \"{target}\" \"secret\"",
              "GitHub repositories containing target secrets",
              "vcs-credential", "critical", ["github", "secret"]),

            t(f"site:github.com \"{target}\" \"token\"",
              "GitHub repositories with target tokens",
              "vcs-credential", "critical", ["github", "token"]),

            t(f"site:github.com \"{target}\" \"DB_PASSWORD\"",
              "GitHub repositories exposing target database password",
              "vcs-credential", "critical", ["github", "database", "password"]),

            t(f"site:github.com \"{target}\" \"private_key\"",
              "GitHub repositories with target private keys",
              "vcs-credential", "critical", ["github", "private-key"]),

            t(f"site:github.com \"{target}\" \"BEGIN RSA PRIVATE KEY\"",
              "GitHub repositories containing RSA private keys for target",
              "vcs-credential", "critical", ["github", "rsa", "private-key"]),

            t(f"site:gitlab.com \"{target}\" \"password\"",
              "GitLab repositories leaking target passwords",
              "vcs-credential", "critical", ["gitlab", "password"]),

            t(f"site:gitlab.com \"{target}\" \"secret\"",
              "GitLab repositories with target secrets",
              "vcs-credential", "critical", ["gitlab", "secret"]),

            t(f"site:bitbucket.org \"{target}\" \"secret\"",
              "Bitbucket repositories with target secrets",
              "vcs-credential", "critical", ["bitbucket", "secret"]),

            t(f"site:{target} intext:\"default password\"",
              "Pages referencing default passwords",
              "default-credential", "high", ["default-password"]),

            t(f"site:{target} intext:\"initial password\"",
              "Pages referencing initial setup passwords",
              "default-credential", "high", ["default-password"]),

            t(f"site:{target} intext:\"password is\"",
              "Pages with 'password is' phrasing — plaintext credential hint",
              "default-credential", "critical", ["password"]),

            t(f"site:{target} intext:\"temporary password\"",
              "Pages with temporary password references",
              "default-credential", "high", ["password", "temporary"]),

            t(f"site:{target} intitle:\"Please change your password\"",
              "Post-login forced password change pages — confirms valid account",
              "default-credential", "medium", ["password-change"]),

            t(f"site:{target} intext:\"admin:admin\" OR intext:\"admin:password\"",
              "Hardcoded default credential pairs in page content",
              "default-credential", "critical", ["default-credential", "admin"]),

            t(f"site:{target} intext:\"root:root\" OR intext:\"root:toor\"",
              "Default root credential pairs exposed",
              "default-credential", "critical", ["default-credential", "root"]),

            t(f"site:{target} filetype:pem",
              "PEM certificate or key files exposed",
              "crypto-credential", "critical", ["pem", "ssl", "crypto"]),

            t(f"site:{target} filetype:key",
              "Generic .key files exposed",
              "crypto-credential", "critical", ["key", "crypto"]),

            t(f"site:{target} filetype:p12",
              "PKCS#12 certificate bundle exposed",
              "crypto-credential", "critical", ["p12", "pkcs12", "ssl"]),

            t(f"site:{target} filetype:pfx",
              "PFX certificate file exposed",
              "crypto-credential", "critical", ["pfx", "ssl"]),

            t(f"site:{target} filetype:crt",
              "Certificate file (.crt) exposed",
              "crypto-credential", "high", ["crt", "ssl"]),

            t(f"site:{target} intext:\"BEGIN RSA PRIVATE KEY\"",
              "RSA private key block in page content",
              "crypto-credential", "critical", ["rsa", "private-key"]),

            t(f"site:{target} intext:\"BEGIN OPENSSH PRIVATE KEY\"",
              "OpenSSH private key block in page content",
              "crypto-credential", "critical", ["ssh", "private-key"]),

            t(f"site:{target} intext:\"BEGIN DSA PRIVATE KEY\"",
              "DSA private key block exposed",
              "crypto-credential", "critical", ["dsa", "private-key"]),

            t(f"site:{target} intext:\"BEGIN EC PRIVATE KEY\"",
              "Elliptic curve private key block exposed",
              "crypto-credential", "critical", ["ec", "private-key"]),

            t(f"site:{target} inurl:id_rsa",
              "SSH id_rsa private key file directly accessible",
              "crypto-credential", "critical", ["ssh", "rsa", "private-key"]),

            t(f"site:{target} inurl:id_dsa",
              "SSH id_dsa private key file directly accessible",
              "crypto-credential", "critical", ["ssh", "dsa", "private-key"]),

            t(f"site:{target} inurl:id_ecdsa",
              "SSH ECDSA private key file directly accessible",
              "crypto-credential", "critical", ["ssh", "ecdsa", "private-key"]),

            t(f"site:{target} inurl:id_ed25519",
              "SSH Ed25519 private key file directly accessible",
              "crypto-credential", "critical", ["ssh", "ed25519", "private-key"]),

            t(f"site:{target} intext:\"Authorization: Basic\"",
              "HTTP Basic auth header value leaked in page content",
              "http-credential", "critical", ["basic-auth", "authorization"]),

            t(f"site:{target} inurl:\"/.htpasswd\"",
              ".htpasswd file accessible — Apache basic auth credentials",
              "http-credential", "critical", ["htpasswd", "apache", "basic-auth"]),

            t(f"site:{target} inurl:\"/.htaccess\"",
              ".htaccess file directly accessible",
              "http-credential", "high", ["htaccess", "apache"]),

            t(f"site:{target} filetype:htpasswd",
              "htpasswd files indexed",
              "http-credential", "critical", ["htpasswd", "basic-auth"]),

            t(f"site:{target} intext:\"mysql_connect\" intext:\"password\"",
              "PHP files exposing MySQL connection with password",
              "database-credential", "critical", ["mysql", "php", "password"]),

            t(f"site:{target} intext:\"pg_connect\" intext:\"password\"",
              "PHP files exposing PostgreSQL connection with password",
              "database-credential", "critical", ["postgresql", "php", "password"]),

            t(f"site:{target} intext:\"mongodb://\" intext:\"password\"",
              "MongoDB connection string with credentials",
              "database-credential", "critical", ["mongodb", "connection-string"]),

            t(f"site:{target} intext:\"redis://\" intext:\"password\"",
              "Redis connection string with credentials",
              "database-credential", "critical", ["redis", "connection-string"]),

            t(f"site:{target} intext:\"jdbc:\" intext:\"password\"",
              "Java JDBC connection string with credentials",
              "database-credential", "critical", ["jdbc", "java", "database"]),

            t(f"site:{target} intext:\"connection string\" intext:\"password\"",
              "Generic connection string with embedded password",
              "database-credential", "critical", ["connection-string", "password"]),

            t(f"site:{target} intext:\"Data Source=\" intext:\"Password=\"",
              ".NET connection string with password parameter",
              "database-credential", "critical", ["dotnet", "mssql", "password"]),

            t(f"site:{target} filetype:json intext:\"password\"",
              "JSON configuration files containing passwords",
              "config-credential", "critical", ["json", "password"]),

            t(f"site:{target} filetype:yaml intext:\"password\"",
              "YAML files containing password fields",
              "config-credential", "critical", ["yaml", "password"]),

            t(f"site:{target} filetype:xml intext:\"password\"",
              "XML configuration with password nodes",
              "config-credential", "critical", ["xml", "password"]),

            t(f"site:{target} filetype:properties intext:\"password\"",
              "Java .properties files with password values",
              "config-credential", "critical", ["java", "properties", "password"]),

            t(f"site:{target} inurl:\"credentials\" filetype:json",
              "JSON files with 'credentials' in the URL",
              "config-credential", "critical", ["credentials", "json"]),

            t(f"site:{target} inurl:\"secrets\" filetype:yaml",
              "YAML secret manifests — common in Kubernetes",
              "config-credential", "critical", ["kubernetes", "secrets", "yaml"]),

            t(f"site:{target} inurl:\"kubeconfig\" OR inurl:\".kube/config\"",
              "Kubernetes cluster configuration file exposed",
              "cloud-credential", "critical", ["kubernetes", "kubeconfig"]),

            t(f"site:{target} intext:\"AZURE_CLIENT_SECRET\"",
              "Azure service principal client secret exposed",
              "cloud-credential", "critical", ["azure", "cloud", "credentials"]),

            t(f"site:{target} intext:\"GOOGLE_APPLICATION_CREDENTIALS\"",
              "Google Cloud service account credentials file reference",
              "cloud-credential", "critical", ["gcp", "cloud", "credentials"]),

            t(f"site:{target} intext:\"GCP_SERVICE_ACCOUNT_KEY\"",
              "GCP service account key exposed",
              "cloud-credential", "critical", ["gcp", "cloud", "credentials"]),

            t(f"site:{target} intext:\"DIGITALOCEAN_TOKEN\"",
              "DigitalOcean personal access token exposed",
              "cloud-credential", "critical", ["digitalocean", "cloud", "token"]),

            t(f"site:{target} intext:\"HEROKU_API_KEY\"",
              "Heroku deployment API key exposed",
              "cloud-credential", "critical", ["heroku", "api-key"]),

            t(f"site:{target} intext:\"GITHUB_TOKEN\" OR intext:\"GH_TOKEN\"",
              "GitHub personal access token exposed",
              "vcs-credential", "critical", ["github", "token"]),

            t(f"site:{target} intext:\"SLACK_TOKEN\" OR intext:\"SLACK_WEBHOOK\"",
              "Slack bot token or incoming webhook URL exposed",
              "api-credential", "critical", ["slack", "token", "webhook"]),

            t(f"site:{target} intext:\"DISCORD_TOKEN\" OR intext:\"DISCORD_WEBHOOK\"",
              "Discord bot token or webhook URL exposed",
              "api-credential", "high", ["discord", "token", "webhook"]),

            t(f"site:{target} intext:\"TELEGRAM_BOT_TOKEN\"",
              "Telegram bot token exposed",
              "api-credential", "high", ["telegram", "bot", "token"]),

            t(f"site:{target} filetype:json intext:\"private_key\" intext:\"client_email\"",
              "Google service account JSON key file",
              "cloud-credential", "critical", ["google", "service-account", "private-key"]),

            t(f"site:{target} inurl:\"serviceAccountKey.json\"",
              "Firebase/GCP service account key file directly accessible",
              "cloud-credential", "critical", ["firebase", "gcp", "service-account"]),

            t(f"site:{target} intext:\"-----BEGIN CERTIFICATE-----\"",
              "Certificate data exposed in page or file content",
              "crypto-credential", "medium", ["certificate", "ssl"]),

            t(f"site:{target} filetype:ovpn OR filetype:conf intext:\"remote\"",
              "OpenVPN configuration files exposed",
              "network-credential", "critical", ["vpn", "openvpn", "network"]),

            t(f"site:{target} filetype:ppk",
              "PuTTY private key files exposed",
              "crypto-credential", "critical", ["putty", "ssh", "private-key"]),

        ]