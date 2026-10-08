from modules.base import BaseModule, DorkTemplate


class ApiAndTestEnvModule(BaseModule):
    name = "apiandtestenv"
    description = "API endpoint and test environment discovery via Google Dorking"

    def dorks(self) -> list[DorkTemplate]:
        t = self._make_dork
        target = "{target}"

        return [

            t(f"site:{target} inurl:\"/api/v1\"",
              "API v1 base path — enumerates versioned REST endpoints",
              "api-endpoint", "medium", ["api", "rest", "v1"]),

            t(f"site:{target} inurl:\"/api/v2\"",
              "API v2 base path",
              "api-endpoint", "medium", ["api", "rest", "v2"]),

            t(f"site:{target} inurl:\"/api/v3\"",
              "API v3 base path",
              "api-endpoint", "medium", ["api", "rest", "v3"]),

            t(f"site:{target} inurl:\"/rest/api\"",
              "REST API root endpoint",
              "api-endpoint", "medium", ["api", "rest"]),

            t(f"site:{target} inurl:\"/graphql\"",
              "GraphQL endpoint — may allow introspection of full schema",
              "api-endpoint", "high", ["graphql", "api"]),

            t(f"site:{target} inurl:\"/graphiql\"",
              "GraphiQL interactive IDE exposed — full schema exploration",
              "api-endpoint", "critical", ["graphql", "graphiql", "api"]),

            t(f"site:{target} inurl:\"/playground\" intitle:\"GraphQL\"",
              "GraphQL Playground tool exposed in production",
              "api-endpoint", "high", ["graphql", "playground", "api"]),

            t(f"site:{target} inurl:\"/swagger\" OR inurl:\"/swagger-ui\"",
              "Swagger UI API documentation exposed",
              "api-docs", "medium", ["swagger", "openapi", "api"]),

            t(f"site:{target} inurl:\"/swagger.json\" OR inurl:\"/swagger.yaml\"",
              "Raw Swagger/OpenAPI specification file accessible",
              "api-docs", "high", ["swagger", "openapi", "api"]),

            t(f"site:{target} inurl:\"/openapi.json\" OR inurl:\"/openapi.yaml\"",
              "OpenAPI 3.x specification file accessible",
              "api-docs", "high", ["openapi", "api"]),

            t(f"site:{target} inurl:\"/api-docs\" filetype:json",
              "API documentation JSON file directly accessible",
              "api-docs", "medium", ["api-docs", "openapi"]),

            t(f"site:{target} inurl:\"/redoc\"",
              "ReDoc API documentation interface exposed",
              "api-docs", "medium", ["redoc", "openapi", "api"]),

            t(f"site:{target} inurl:\"/api/swagger\" OR inurl:\"/docs/swagger\"",
              "Swagger docs at non-standard path",
              "api-docs", "medium", ["swagger", "api"]),

            t(f"site:{target} inurl:\"wsdl\" filetype:wsdl",
              "WSDL service description file — enumerates SOAP operations",
              "api-docs", "medium", ["wsdl", "soap", "api"]),

            t(f"site:{target} inurl:\"/api\" intext:\"token\" filetype:json",
              "API JSON responses containing token fields",
              "api-credential", "critical", ["api", "token", "json"]),

            t(f"site:{target} inurl:\"/api/users\" OR inurl:\"/api/accounts\"",
              "User or account listing API endpoint",
              "api-endpoint", "high", ["api", "users", "enumeration"]),

            t(f"site:{target} inurl:\"/api/admin\"",
              "Admin-scoped API endpoint",
              "api-endpoint", "critical", ["api", "admin"]),

            t(f"site:{target} inurl:\"/api/debug\"",
              "Debug API endpoint left accessible",
              "api-endpoint", "high", ["api", "debug"]),

            t(f"site:{target} inurl:\"/api/health\" OR inurl:\"/health\"",
              "Health check endpoint may expose service details",
              "api-endpoint", "low", ["api", "health"]),

            t(f"site:{target} inurl:\"/api/status\" OR inurl:\"/status\"",
              "Status endpoint may expose internal component information",
              "api-endpoint", "low", ["api", "status"]),

            t(f"site:{target} inurl:\"/api/config\"",
              "Configuration endpoint exposed via API",
              "api-endpoint", "critical", ["api", "config"]),

            t(f"site:{target} inurl:\"/api/logs\" OR inurl:\"/api/log\"",
              "Log data accessible via API endpoint",
              "api-endpoint", "critical", ["api", "logs"]),

            t(f"site:{target} inurl:\"/api/keys\" OR inurl:\"/api/token\"",
              "API key or token management endpoints",
              "api-endpoint", "critical", ["api", "keys", "token"]),

            t(f"site:{target} inurl:\"dev.\" OR inurl:\"development.\"",
              "Development subdomain or environment exposed publicly",
              "test-env", "high", ["dev", "development", "environment"]),

            t(f"site:dev.{target}",
              "dev. subdomain — development environment indexed",
              "test-env", "high", ["dev", "subdomain", "environment"]),

            t(f"site:staging.{target}",
              "staging. subdomain — staging environment indexed",
              "test-env", "high", ["staging", "subdomain", "environment"]),

            t(f"site:test.{target}",
              "test. subdomain — test environment indexed",
              "test-env", "high", ["test", "subdomain", "environment"]),

            t(f"site:uat.{target}",
              "uat. subdomain — user acceptance testing environment indexed",
              "test-env", "high", ["uat", "subdomain", "environment"]),

            t(f"site:qa.{target}",
              "qa. subdomain — QA environment indexed",
              "test-env", "high", ["qa", "subdomain", "environment"]),

            t(f"site:beta.{target}",
              "beta. subdomain publicly indexed",
              "test-env", "medium", ["beta", "subdomain"]),

            t(f"site:sandbox.{target}",
              "sandbox. subdomain — may contain real data or credentials",
              "test-env", "high", ["sandbox", "subdomain", "environment"]),

            t(f"site:demo.{target}",
              "demo. subdomain — may use default or weak credentials",
              "test-env", "medium", ["demo", "subdomain"]),

            t(f"site:preprod.{target}",
              "preprod. subdomain — pre-production environment indexed",
              "test-env", "high", ["preprod", "subdomain", "environment"]),

            t(f"site:{target} inurl:\"staging\" OR inurl:\"stage\"",
              "Staging paths within the main domain",
              "test-env", "high", ["staging", "environment"]),

            t(f"site:{target} inurl:\"test\" inurl:\"api\"",
              "Test API paths accessible on production domain",
              "test-env", "high", ["test", "api", "environment"]),

            t(f"site:{target} inurl:\"sandbox\" inurl:\"api\"",
              "Sandbox API endpoints",
              "test-env", "high", ["sandbox", "api"]),

            t(f"site:{target} inurl:\"/v1/internal\" OR inurl:\"/internal/api\"",
              "Internal API routes exposed externally",
              "api-endpoint", "critical", ["api", "internal"]),

            t(f"site:{target} inurl:\"/private/api\" OR inurl:\"/api/private\"",
              "Private API endpoints accessible without authentication check",
              "api-endpoint", "critical", ["api", "private"]),

            t(f"site:{target} intext:\"API_KEY\" filetype:js",
              "JavaScript files with API_KEY variable references",
              "api-credential", "critical", ["api-key", "javascript"]),

            t(f"site:{target} intext:\"apiKey\" filetype:js",
              "JavaScript source with camelCase apiKey assignment",
              "api-credential", "critical", ["api-key", "javascript"]),

            t(f"site:{target} intext:\"client_id\" intext:\"client_secret\"",
              "OAuth client credentials exposed in page content",
              "api-credential", "critical", ["oauth", "client-secret"]),

            t(f"site:{target} intext:\"grant_type\" intext:\"client_credentials\"",
              "OAuth machine-to-machine flow credential references",
              "api-credential", "high", ["oauth", "credentials"]),

            t(f"site:{target} filetype:json intext:\"access_token\"",
              "JSON files containing access tokens",
              "api-credential", "critical", ["token", "json", "oauth"]),

            t(f"site:{target} filetype:json intext:\"refresh_token\"",
              "JSON files containing refresh tokens",
              "api-credential", "critical", ["token", "json", "oauth"]),

            t(f"site:{target} inurl:\"/oauth/token\" OR inurl:\"/oauth2/token\"",
              "OAuth token endpoint publicly accessible",
              "api-endpoint", "medium", ["oauth", "token", "api"]),

            t(f"site:{target} inurl:\"/oauth/authorize\"",
              "OAuth authorization endpoint indexed",
              "api-endpoint", "medium", ["oauth", "authorize", "api"]),

            t(f"site:{target} inurl:\"/auth/callback\" OR inurl:\"/oauth/callback\"",
              "OAuth callback URL exposed — verify SSRF and open-redirect risk",
              "api-endpoint", "medium", ["oauth", "callback", "api"]),

            t(f"site:{target} inurl:\"/api\" intitle:\"403 Forbidden\"",
              "API paths returning 403 — confirms endpoint exists behind auth",
              "api-endpoint", "low", ["api", "403", "recon"]),

            t(f"site:{target} inurl:\"/api\" intitle:\"401 Unauthorized\"",
              "API paths returning 401 — endpoint confirmed, auth required",
              "api-endpoint", "low", ["api", "401", "recon"]),

            t(f"site:{target} filetype:yaml intext:\"openapi:\" OR intext:\"swagger:\"",
              "YAML-formatted OpenAPI specification file",
              "api-docs", "high", ["openapi", "swagger", "yaml"]),

            t(f"site:{target} inurl:\"/api/schema\" OR inurl:\"/schema.json\"",
              "API schema endpoint — may expose full data model",
              "api-docs", "medium", ["api", "schema"]),

            t(f"site:{target} intext:\"postman\" filetype:json",
              "Postman collection JSON file — contains API endpoints and example requests",
              "api-docs", "high", ["postman", "api", "collection"]),

            t(f"site:{target} inurl:\"/api/export\" OR inurl:\"/api/download\"",
              "Data export/download API endpoints",
              "api-endpoint", "high", ["api", "export", "data"]),

            t(f"site:{target} inurl:\"/api/backup\"",
              "Backup API endpoint — may expose sensitive data dumps",
              "api-endpoint", "critical", ["api", "backup"]),

            t(f"site:{target} inurl:\"/internal\" intitle:\"Index of\"",
              "Internal directory listing exposed",
              "test-env", "critical", ["internal", "directory-listing"]),

            t(f"site:{target} inurl:\"/dev\" intitle:\"Index of\"",
              "Development directory listing exposed",
              "test-env", "high", ["dev", "directory-listing"]),

            t(f"site:{target} inurl:\"/mock\" OR inurl:\"/mocks\"",
              "Mock API or mock data endpoints",
              "test-env", "medium", ["mock", "api", "test"]),

            t(f"site:{target} inurl:\"/fixtures\" OR inurl:\"/seeders\"",
              "Test fixture or seeder data exposed",
              "test-env", "high", ["fixtures", "test-data"]),

            t(f"site:{target} inurl:\"/storybook\" OR intitle:\"Storybook\"",
              "Storybook UI component library exposed — reveals frontend architecture",
              "test-env", "medium", ["storybook", "frontend", "recon"]),

        ]