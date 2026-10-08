from modules.base import BaseModule, DorkTemplate


class ServerAndTechModule(BaseModule):
    name = "serverandtech"
    description = "Server and technology fingerprinting via Google Dorking"

    def dorks(self) -> list[DorkTemplate]:
        t = self._make_dork
        target = "{target}"

        return [

            t(f"site:{target} intitle:\"Apache HTTP Server\" intext:\"Apache\"",
              "Apache HTTP Server default or status pages",
              "web-server", "medium", ["apache", "server"]),

            t(f"site:{target} intitle:\"Welcome to nginx\"",
              "Nginx default welcome page exposed",
              "web-server", "medium", ["nginx", "server"]),

            t(f"site:{target} intitle:\"IIS Windows Server\"",
              "Microsoft IIS default page exposed",
              "web-server", "medium", ["iis", "windows", "server"]),

            t(f"site:{target} intitle:\"Apache Tomcat\" intext:\"Tomcat\"",
              "Apache Tomcat manager or status page",
              "web-server", "high", ["tomcat", "java", "server"]),

            t(f"site:{target} inurl:\"server-status\" intitle:\"Apache Status\"",
              "Apache mod_status page publicly accessible",
              "web-server", "high", ["apache", "server-status"]),

            t(f"site:{target} inurl:\"nginx_status\"",
              "Nginx stub_status module endpoint exposed",
              "web-server", "high", ["nginx", "server-status"]),

            t(f"site:{target} intitle:\"Jetty\" intext:\"Powered by Jetty\"",
              "Eclipse Jetty servlet container default page",
              "web-server", "medium", ["jetty", "java", "server"]),

            t(f"site:{target} intitle:\"Lighttpd\" intext:\"lighttpd\"",
              "Lighttpd web server default or error page",
              "web-server", "medium", ["lighttpd", "server"]),

            t(f"site:{target} intext:\"X-Powered-By: PHP\" filetype:php",
              "PHP-powered pages leaking version header in body",
              "language-framework", "medium", ["php", "version"]),

            t(f"site:{target} intext:\"ASP.NET\" inurl:\".aspx\"",
              "ASP.NET application pages",
              "language-framework", "low", ["aspnet", "dotnet"]),

            t(f"site:{target} intext:\"Powered by Django\"",
              "Django framework version disclosure",
              "language-framework", "medium", ["django", "python"]),

            t(f"site:{target} intext:\"Powered by Ruby on Rails\"",
              "Ruby on Rails framework disclosure",
              "language-framework", "medium", ["rails", "ruby"]),

            t(f"site:{target} intext:\"Powered by Laravel\"",
              "Laravel PHP framework disclosure",
              "language-framework", "medium", ["laravel", "php"]),

            t(f"site:{target} intext:\"Powered by Express\"",
              "Node.js Express framework disclosure",
              "language-framework", "medium", ["express", "nodejs"]),

            t(f"site:{target} intext:\"Spring Boot\" intitle:\"Whitelabel Error Page\"",
              "Spring Boot whitelabel error page — reveals framework and stack trace",
              "language-framework", "high", ["spring", "java", "error"]),

            t(f"site:{target} intitle:\"phpinfo()\" intext:\"PHP Version\"",
              "phpinfo() output publicly accessible — full server environment dump",
              "debug-exposure", "critical", ["php", "phpinfo", "version"]),

            t(f"site:{target} intitle:\"PHP Error\" intext:\"Fatal error\"",
              "PHP fatal error pages leaking file paths and stack traces",
              "debug-exposure", "high", ["php", "error", "path-disclosure"]),

            t(f"site:{target} intitle:\"Whoops\" intext:\"Stack trace\"",
              "Whoops PHP error handler debug page exposed",
              "debug-exposure", "high", ["php", "whoops", "stacktrace"]),

            t(f"site:{target} intitle:\"Debug\" intext:\"Traceback\" intext:\"Python\"",
              "Python traceback debug page exposed in production",
              "debug-exposure", "high", ["python", "traceback", "debug"]),

            t(f"site:{target} intitle:\"Django Debug\" intext:\"Traceback\"",
              "Django DEBUG=True error page with stack trace",
              "debug-exposure", "critical", ["django", "debug", "stacktrace"]),

            t(f"site:{target} intext:\"java.lang.NullPointerException\" filetype:html",
              "Java NullPointerException stack trace in HTML response",
              "debug-exposure", "high", ["java", "exception", "stacktrace"]),

            t(f"site:{target} intitle:\"500 Internal Server Error\" intext:\"stack trace\"",
              "HTTP 500 pages exposing internal stack trace",
              "debug-exposure", "high", ["error", "stacktrace"]),

            t(f"site:{target} inurl:phpMyAdmin intitle:\"phpMyAdmin\"",
              "phpMyAdmin database management interface exposed",
              "admin-panel", "critical", ["phpmyadmin", "mysql", "admin"]),

            t(f"site:{target} intitle:\"Adminer\" intext:\"adminer\"",
              "Adminer database administration tool exposed",
              "admin-panel", "critical", ["adminer", "database", "admin"]),

            t(f"site:{target} intitle:\"pgAdmin\" inurl:pgadmin",
              "pgAdmin PostgreSQL management interface exposed",
              "admin-panel", "critical", ["pgadmin", "postgresql", "admin"]),

            t(f"site:{target} intitle:\"Mongo Express\" intext:\"db.\"",
              "Mongo Express MongoDB admin interface exposed",
              "admin-panel", "critical", ["mongodb", "mongo-express", "admin"]),

            t(f"site:{target} inurl:\"/redis\" intitle:\"Redis Commander\"",
              "Redis Commander web UI exposed",
              "admin-panel", "critical", ["redis", "admin"]),

            t(f"site:{target} intitle:\"Grafana\" inurl:\"/login\"",
              "Grafana monitoring dashboard login page",
              "admin-panel", "high", ["grafana", "monitoring"]),

            t(f"site:{target} intitle:\"Kibana\" inurl:\"/app/kibana\"",
              "Kibana Elasticsearch dashboard exposed",
              "admin-panel", "high", ["kibana", "elasticsearch", "logging"]),

            t(f"site:{target} intitle:\"Prometheus\" inurl:\"/-/healthy\"",
              "Prometheus metrics server exposed",
              "admin-panel", "high", ["prometheus", "monitoring"]),

            t(f"site:{target} inurl:\"/metrics\" intitle:\"Prometheus\"",
              "Prometheus /metrics endpoint publicly accessible",
              "admin-panel", "high", ["prometheus", "metrics"]),

            t(f"site:{target} intitle:\"RabbitMQ Management\"",
              "RabbitMQ management console exposed",
              "admin-panel", "critical", ["rabbitmq", "message-queue", "admin"]),

            t(f"site:{target} intitle:\"Kubernetes Dashboard\"",
              "Kubernetes web dashboard exposed",
              "admin-panel", "critical", ["kubernetes", "k8s", "admin"]),

            t(f"site:{target} intitle:\"Jenkins\" inurl:\"/job\"",
              "Jenkins CI/CD build server interface exposed",
              "admin-panel", "high", ["jenkins", "cicd"]),

            t(f"site:{target} intitle:\"SonarQube\" inurl:\"/sessions/new\"",
              "SonarQube code quality platform login exposed",
              "admin-panel", "high", ["sonarqube", "devops"]),

            t(f"site:{target} intitle:\"Portainer\" inurl:\"/#!/auth\"",
              "Portainer Docker management UI login exposed",
              "admin-panel", "critical", ["portainer", "docker", "admin"]),

            t(f"site:{target} inurl:\"/wp-json/wp/v2\" filetype:json",
              "WordPress REST API endpoint exposed — enumerates users and posts",
              "cms-fingerprint", "medium", ["wordpress", "rest-api"]),

            t(f"site:{target} inurl:\"/wp-content/plugins\" intitle:\"Index of\"",
              "WordPress plugins directory listing enabled",
              "cms-fingerprint", "medium", ["wordpress", "plugins", "directory-listing"]),

            t(f"site:{target} inurl:\"/joomla\" OR inurl:\"/components/com_\"",
              "Joomla CMS installation fingerprinted",
              "cms-fingerprint", "low", ["joomla", "cms"]),

            t(f"site:{target} inurl:\"/sites/default/files\" intitle:\"Index of\"",
              "Drupal public files directory listing exposed",
              "cms-fingerprint", "high", ["drupal", "cms", "directory-listing"]),

            t(f"site:{target} inurl:\"/magento\" OR intext:\"Powered by Magento\"",
              "Magento e-commerce platform fingerprinted",
              "cms-fingerprint", "low", ["magento", "ecommerce"]),

            t(f"site:{target} inurl:\"/opencart\" OR intext:\"Powered by OpenCart\"",
              "OpenCart e-commerce platform fingerprinted",
              "cms-fingerprint", "low", ["opencart", "ecommerce"]),

            t(f"site:{target} inurl:\"/robots.txt\"",
              "robots.txt may reveal hidden paths and internal structure",
              "recon-file", "low", ["robots", "recon"]),

            t(f"site:{target} inurl:\"/sitemap.xml\"",
              "sitemap.xml enumerates all indexed URLs",
              "recon-file", "low", ["sitemap", "recon"]),

            t(f"site:{target} inurl:\"/.well-known/security.txt\"",
              "security.txt reveals responsible disclosure contact and policy",
              "recon-file", "info", ["security-txt", "disclosure"]),

            t(f"site:{target} inurl:\"/crossdomain.xml\"",
              "crossdomain.xml may allow overly broad cross-origin access",
              "recon-file", "medium", ["crossdomain", "cors"]),

            t(f"site:{target} inurl:\"/web.config\"",
              "ASP.NET web.config file directly accessible",
              "config-exposure", "critical", ["aspnet", "config", "iis"]),

            t(f"site:{target} inurl:\"/app.config\" OR inurl:\"/applicationHost.config\"",
              ".NET application configuration files exposed",
              "config-exposure", "critical", ["dotnet", "config"]),

            t(f"site:{target} filetype:wsdl OR inurl:\"?wsdl\"",
              "WSDL files revealing SOAP web service endpoints and operations",
              "api-fingerprint", "medium", ["wsdl", "soap", "api"]),

            t(f"site:{target} inurl:\"/actuator\" intitle:\"Actuator\"",
              "Spring Boot Actuator endpoints exposed — health, env, beans",
              "debug-exposure", "critical", ["spring", "actuator", "java"]),

            t(f"site:{target} inurl:\"/actuator/env\"",
              "Spring Boot /actuator/env leaks environment variables",
              "debug-exposure", "critical", ["spring", "actuator", "env"]),

            t(f"site:{target} inurl:\"/actuator/heapdump\"",
              "Spring Boot heap dump endpoint — full JVM memory snapshot",
              "debug-exposure", "critical", ["spring", "actuator", "heapdump"]),

            t(f"site:{target} inurl:\"/__debug__/\"",
              "Django debug toolbar exposed in production",
              "debug-exposure", "high", ["django", "debug"]),

            t(f"site:{target} inurl:\"/telescope\" intitle:\"Laravel Telescope\"",
              "Laravel Telescope debug dashboard accessible without auth",
              "debug-exposure", "critical", ["laravel", "telescope", "debug"]),

            t(f"site:{target} inurl:\"/horizon\" intitle:\"Laravel Horizon\"",
              "Laravel Horizon queue dashboard exposed",
              "admin-panel", "high", ["laravel", "horizon", "queue"]),

            t(f"site:{target} intext:\"Server: Apache\" intext:\"X-Powered-By:\"",
              "Server response headers reflected in page body — version disclosure",
              "version-disclosure", "medium", ["apache", "headers", "version"]),

            t(f"site:{target} inurl:\"/info.php\" intitle:\"phpinfo\"",
              "info.php exposing full PHP environment details",
              "debug-exposure", "critical", ["php", "phpinfo"]),

            t(f"site:{target} inurl:\"/test.php\"",
              "test.php development file left on production server",
              "debug-exposure", "high", ["php", "test-file"]),

            t(f"site:{target} inurl:\"/debug.php\"",
              "debug.php file accessible on production server",
              "debug-exposure", "high", ["php", "debug"]),

            t(f"site:{target} inurl:\"/console\" intitle:\"Grails\"",
              "Grails Groovy console exposed — remote code execution risk",
              "debug-exposure", "critical", ["grails", "groovy", "rce"]),

            t(f"site:{target} inurl:\"/.env.example\" OR inurl:\"/.env.sample\"",
              "Example environment file leaks expected variable names",
              "config-exposure", "medium", ["env", "config", "recon"]),

            t(f"site:{target} inurl:\"/CHANGELOG\" OR inurl:\"/CHANGELOG.md\"",
              "Changelog file reveals version history and software version",
              "version-disclosure", "low", ["changelog", "version"]),

            t(f"site:{target} inurl:\"/VERSION\" OR inurl:\"/version.txt\"",
              "Version file directly accessible — pinpoints software release",
              "version-disclosure", "medium", ["version", "recon"]),

            t(f"site:{target} inurl:\"/README\" OR inurl:\"/README.md\"",
              "README file reveals project structure and technology stack",
              "version-disclosure", "low", ["readme", "recon"]),

        ]