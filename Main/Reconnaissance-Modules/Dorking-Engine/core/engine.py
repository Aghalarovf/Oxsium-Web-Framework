import importlib
from typing import Optional
from core.logger import Logger
from core.requester import Requester
from core.exporter import Exporter


MODULE_MAP = {
    "fileanddirectory": "modules.fileanddirectory",
    "credentialandauth": "modules.credentialandauth",
    "serverandtech":    "modules.serverandtech",
    "apiandtestenv":    "modules.apiandtestenv",
    "sensdata":         "modules.sensdata",
}


class Engine:
    def __init__(
        self,
        target: str,
        modules: list[str],
        output: Optional[str],
        fmt: str,
        delay: float,
        timeout: int,
        proxy: Optional[str],
        serpapi_key: Optional[str],
        dry_run: bool,
        verbose: bool,
    ):
        self.target = target
        self.modules = modules
        self.output = output
        self.fmt = fmt
        self.dry_run = dry_run
        self.verbose = verbose

        self.logger = Logger()
        self.logger.set_verbose(verbose)

        self.requester = Requester(
            delay=delay,
            timeout=timeout,
            proxy=proxy,
            serpapi_key=serpapi_key,
        )

        self.exporter = Exporter()
        self.results: list[dict] = []

    def _load_module(self, module_key: str):
        module_path = MODULE_MAP[module_key]
        mod = importlib.import_module(module_path)

        from modules.base import BaseModule
        for attr_name in dir(mod):
            attr = getattr(mod, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseModule)
                and attr is not BaseModule
            ):
                return attr

        raise ImportError(f"No valid module class found in {module_path}")

    def _run_single_module(self, module_key: str):
        self.logger.info(f"Loading module: {module_key}")

        ModuleClass = self._load_module(module_key)
        instance = ModuleClass(
            target=self.target,
            requester=self.requester,
            logger=self.logger,
            dry_run=self.dry_run,
        )

        self.logger.info(f"Running module: {instance.name}")
        module_results = instance.run()

        for result in module_results:
            result["module"] = instance.name
            self.results.append(result)

        self.logger.success(
            f"Module '{instance.name}' finished. "
            f"Found {len(module_results)} result(s)."
        )

    def run(self):
        self.logger.info("Engine started.")

        for key in self.modules:
            self._run_single_module(key)

        self.logger.info(f"Total results collected: {len(self.results)}")

        if self.output:
            self.exporter.export(
                results=self.results,
                fmt=self.fmt,
                path=self.output,
                target=self.target,
            )
            self.logger.success(f"Results exported to: {self.output}")
        else:
            self._print_results()

    def _print_results(self):
        if not self.results:
            self.logger.warning("No results found.")
            return

        print("\n" + "=" * 70)
        for r in self.results:
            module_label = r.get("module", "unknown")
            dork = r.get("dork", "")
            description = r.get("description", "")
            url = r.get("url", "")

            print(f"[{module_label}] {description}")
            print(f"  Dork : {dork}")
            if url:
                print(f"  URL  : {url}")
            print()
        print("=" * 70)