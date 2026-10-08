import time
from typing import List, Optional
from .logger import ScanLogger
from .network import TLSConnection
from .exporter import Exporter


class Scanner:
    def __init__(self, args, logger: ScanLogger):
        self.args = args
        self.logger = logger
        self.connection = TLSConnection(
            host=args.domain,
            port=args.port,
            sni=args.sni,
            timeout=args.timeout,
            starttls=getattr(args, "starttls", None),
        )
        self.exporter = Exporter(
            domain=args.domain,
            port=args.port,
            sni=args.sni,
        )
        self._modules = self._load_modules()

    def _load_modules(self) -> List:
        modules = []
        args = self.args

        if args.certs:
            from modules.certs import CertificateModule
            modules.append(CertificateModule(self.connection, self.logger))

        if args.protocols:
            from modules.protocols import ProtocolModule
            modules.append(ProtocolModule(self.connection, self.logger))

        if args.ciphers:
            try:
                from modules.ciphers import CipherModule
                modules.append(CipherModule(self.connection, self.logger))
            except ImportError:
                self.logger.warning("CipherModule not yet implemented, skipping --ciphers")

        if args.pfs:
            try:
                from modules.pfs import PfsModule
                modules.append(PfsModule(self.connection, self.logger))
            except ImportError:
                self.logger.warning("PFSModule not yet implemented, skipping --pfs")

        if args.headers:
            try:
                from modules.headers import CertHeaderModule
                modules.append(CertHeaderModule(self.connection, self.logger))
            except ImportError:
                self.logger.warning("HeadersModule not yet implemented, skipping --headers")

        if args.groups:
            try:
                from modules.groups import GroupsModule
                modules.append(GroupsModule(self.connection, self.logger))
            except ImportError:
                self.logger.warning("GroupsModule not yet implemented, skipping --groups")

        if args.fallback:
            try:
                from modules.fallback import FallbackModule
                modules.append(FallbackModule(self.connection, self.logger))
            except ImportError:
                self.logger.warning("FallbackModule not yet implemented, skipping --fallback")

        if args.network:
            try:
                from modules.network_checks import NetworkModule
                modules.append(NetworkModule(self.connection, self.logger))
            except ImportError:
                self.logger.warning("NetworkModule not yet implemented, skipping --network")

        return modules

    def run(self) -> Exporter:
        if not getattr(self.args, "quiet", False):
            self.logger.banner(self.args.domain, self.args.port, self.args.sni)

        total = len(self._modules)
        if total == 0:
            self.logger.warning("No modules selected. Use --help for usage.")
            return self.exporter

        scan_start = time.monotonic()

        for idx, module in enumerate(self._modules, 1):
            name = module.name
            if not getattr(self.args, "quiet", False):
                self.logger.info(f"[{idx}/{total}] Running module: {name}")
            try:
                t0 = time.monotonic()
                result = module.run()
                elapsed = round((time.monotonic() - t0) * 1000, 1)
                self.logger.debug(f"{name} completed in {elapsed} ms")
                self.exporter.add_module_result(name, result)
            except Exception as e:
                self.logger.error(f"Module {name} failed: {e}")
                self.exporter.add_module_result(name, {"error": str(e)})

        total_elapsed = round(time.monotonic() - scan_start, 2)
        if not getattr(self.args, "quiet", False):
            self.logger.info(f"Scan complete in {total_elapsed}s")

        return self.exporter