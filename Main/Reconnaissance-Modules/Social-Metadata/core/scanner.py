import time
from pathlib import Path

from .cli import ScanConfig
from .exporter import Exporter
from .logger import Logger
from .traffic import TrafficStore

_JSON_OUTPUT = Path(__file__).parent.parent.parent.parent / "Scan-Results" / "social_metadata_results.json"


class Scanner:
    def __init__(self, config: ScanConfig, logger: Logger):
        self._config = config
        self._logger = logger
        self._exporter = None

    def _selected_modules(self) -> list[str]:
        c = self._config
        if c.all_modules or not any([c.social, c.emails, c.meta, c.docs]):
            return ["social", "emails", "html_meta", "docs_osint"]
        selected = []
        if c.social:
            selected.append("social")
        if c.emails:
            selected.append("emails")
        if c.meta:
            selected.append("html_meta")
        if c.docs:
            selected.append("docs_osint")
        return selected

    async def run(self) -> dict:
        start = time.monotonic()
        store = TrafficStore(
            paths=self._config.intercept_files,
            target=self._config.target,
            logger=self._logger,
        )
        if not store.load():
            self._logger.warning("No usable records found in the traffic file(s).")
            return {}

        self._logger.section(f"Offline analysis of {store.target}")
        self._exporter = Exporter(store.target)

        for name in self._selected_modules():
            await self._run_module(name, store)

        elapsed = round(time.monotonic() - start, 2)
        self._logger.section(f"Analysis completed in {elapsed}s")
        report = self._exporter._build_report()

        if self._config.json_output:
            _JSON_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            self._exporter.to_json(str(_JSON_OUTPUT), strip_dorks=True)
            self._logger.success(f"Results saved to {_JSON_OUTPUT}")

        return report

    async def _run_module(self, name: str, store: TrafficStore):
        try:
            from modules import load_module
            module = load_module(
                name,
                target=store.target,
                traffic=store,
                logger=self._logger,
                config=self._config,
            )
            self._logger.info(f"Running module: {name}")
            result = await module.run()
            self._exporter.add_module_result(name, result)
            count = len(result) if isinstance(result, (list, dict)) else 1
            self._logger.success(f"Module [{name}] completed - {count} finding(s)")
        except ImportError as exc:
            self._logger.error(f"Module [{name}] not found: {exc}")
        except Exception as exc:
            self._logger.error(f"Module [{name}] failed: {exc}")
            if self._config.verbose:
                import traceback
                traceback.print_exc()
