import argparse
import asyncio
from typing import Any

from core.logger import Logger
from core.requester import Requester
from core.exporter import Exporter

MODULE_REGISTRY: dict[str, str] = {
    "sources": ("modules.sources_fetcher", "ArchiveSourcesModule"),
    "urls":    ("modules.url_analyzer",    "URLAnalyzerModule"),
    "params":  ("modules.param_miner",     "ParamMinerModule"),
    "cdx":     ("modules.cdx_query",       "CDXQueryModule"),
    "diff":    ("modules.snapshot_diff",   "SnapshotDiffModule"),
}


def _import_module_class(module_path: str, class_name: str):
    import importlib
    mod = importlib.import_module(module_path)
    return getattr(mod, class_name)


class ArchiveEngine:

    def __init__(self, args: argparse.Namespace, logger: Logger):
        self.args = args
        self.logger = logger
        self.domain: str = args.domain.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
        self.results: dict[str, Any] = {}

    async def run(self):
        self.logger.start_timer()
        self.logger.info(f"Target: {self.domain}")

        active = self._resolve_active_modules()
        if not active:
            self.logger.error(
                "No module selected. "
                "Use --sources / --urls / --params / --cdx / --diff / --all. "
                "(--all: sources, params, diff işlədir; cdx ayrıca --cdx ilə işlədilə bilər)"
            )
            return

        self.logger.info(f"Active modules: {', '.join(active)}")

        requester_cfg = dict(
            logger=self.logger,
            concurrency=self.args.concurrency,
            timeout=self.args.timeout,
            retries=self.args.retries,
            delay=self.args.delay,
        )

        async with Requester(**requester_cfg) as requester:
            for name in active:
                await self._run_module(name, requester)

        self._finalize()

    # --all verildiкdə işə düşən modullar (cdx xaric)
    ALL_MODULES: list[str] = ["sources", "params", "diff"]

    def _resolve_active_modules(self) -> list[str]:
        if getattr(self.args, "all", False):
            return [m for m in self.ALL_MODULES if m in MODULE_REGISTRY]

        active = []
        for name in MODULE_REGISTRY:
            if getattr(self.args, name, False):
                active.append(name)
        return active

    async def _run_module(self, name: str, requester: Requester):
        module_path, class_name = MODULE_REGISTRY[name]

        try:
            ModuleClass = _import_module_class(module_path, class_name)
        except (ImportError, AttributeError) as e:
            self.logger.warning(f"Failed to load module [{name}]: {e}")
            return

        self.logger.section(f"MODULE: {name.upper()}")

        try:
            instance = ModuleClass(
                domain=self.domain,
                requester=requester,
                logger=self.logger,
                args=self.args,
                prior_results=self.results,
            )

            if name == "params":
                urls = self._extract_urls_from_results()
                self.logger.info(f"[params] {len(urls)} URL əvvəlki modullardan ötürüldü")
                result = await instance.run(urls=urls)
            else:
                result = await instance.run()

            if result:
                self.results[name] = result
                self.logger.success(
                    f"[{name}] completed — "
                    f"{self._count_result(result)} findings"
                )
        except Exception as exc:
            self.logger.error(f"[{name}] module error: {exc}")
            if self.args.verbose:
                import traceback
                traceback.print_exc()

    def _extract_urls_from_results(self) -> list[str]:
        """Əvvəlki modulların nəticəsindən bütün URL-ləri toplayır."""
        urls: list[str] = []
        seen: set[str] = set()

        def _collect(obj: Any) -> None:
            if isinstance(obj, str):
                if obj.startswith("http") and obj not in seen:
                    seen.add(obj)
                    urls.append(obj)
            elif isinstance(obj, list):
                for item in obj:
                    _collect(item)
            elif isinstance(obj, dict):
                for v in obj.values():
                    _collect(v)

        for module_name in ("sources", "urls", "cdx"):
            if module_name in self.results:
                _collect(self.results[module_name])

        return urls

    def _finalize(self):
        stats = {
            "Domain": self.domain,
            "Processed Modules": len(self.results),
        }
        for module_name, data in self.results.items():
            stats[f"  [{module_name}] findings"] = self._count_result(data)

        self.logger.summary(stats)

        if self.args.output or self.args.format != "json":
            exporter = Exporter(
                logger=self.logger,
                output_path=self.args.output,
                fmt=self.args.format,
            )
            exporter.export(self.results, label=self.domain.replace(".", "_"))

        if getattr(self.args, "wordlist", False) and "params" in self.results:
            exporter = Exporter(
                logger=self.logger,
                output_path=self.args.output,
                fmt="wordlist",
            )
            param_data = self.results["params"].get("all_params", [])
            exporter.export_wordlist(param_data)

    @staticmethod
    def _count_result(data: Any) -> int:
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            counts = [len(v) for v in data.values() if isinstance(v, (list, dict))]
            return max(counts, default=len(data))
        return 0