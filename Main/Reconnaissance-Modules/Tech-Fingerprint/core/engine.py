from core.logger import get_logger
from core.exporter import export

logger = get_logger()


class Engine:
    def __init__(self, domain: str, modules: list, output_path: str = None):
        self.domain = domain
        self.modules = modules
        self.output_path = output_path
        self.results = {}

    def run(self) -> dict:
        logger.info(f"Starting scan on: {self.domain}")
        logger.info(f"Active modules: {[m.__class__.__name__ for m in self.modules]}")

        for module in self.modules:
            name = module.__class__.__name__
            logger.info(f"Running module: {name}")
            try:
                result = module.run(self.domain)
                self.results[name] = result
                logger.info(f"Module {name} completed")
            except Exception as e:
                logger.error(f"Module {name} failed: {e}")
                self.results[name] = {"error": str(e)}

        output_file = export(self.domain, self.results, output_path=self.output_path)
        return {"output_file": output_file, "results": self.results}