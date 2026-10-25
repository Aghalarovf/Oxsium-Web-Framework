import importlib
import inspect
import pkgutil
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List

from core.auth import Credentials, close_session, establish_session
from core.config import EngineConfig
from core.exceptions import ConfigError, OxSMBError
from core.logger import OxLogger
from core.output import JSONOutputWriter
from core.smb_targets import Target, build_target_list

import modules.common as common_modules_package
import modules.domain_controller as domain_controller_modules_package
import modules.system_info as system_info_modules_package
import modules.vulnerabilities as vulnerabilities_modules_package
from modes import aggressive, custom, normal, stealth, ultra

MODE_REGISTRY = {
    "stealth": stealth.MODE_PROFILE,
    "normal": normal.MODE_PROFILE,
    "aggressive": aggressive.MODE_PROFILE,
    "ultra": ultra.MODE_PROFILE,
}


def discover_modules_in_package(package) -> Dict[str, Callable]:
    discovered = {}
    for _, module_name, is_pkg in pkgutil.iter_modules(package.__path__):
        if is_pkg:
            continue
        full_name = f"{package.__name__}.{module_name}"
        module = importlib.import_module(full_name)
        if hasattr(module, "run"):
            discovered[module_name] = module.run
    return discovered


def discover_common_modules() -> Dict[str, Callable]:
    return discover_modules_in_package(common_modules_package)


def discover_system_info_modules() -> Dict[str, Callable]:
    return discover_modules_in_package(system_info_modules_package)


def discover_domain_controller_modules() -> Dict[str, Callable]:
    return discover_modules_in_package(domain_controller_modules_package)


def discover_vulnerabilities_modules() -> Dict[str, Callable]:
    return discover_modules_in_package(vulnerabilities_modules_package)


def resolve_mode_profile(
    config: EngineConfig,
    all_modules: Dict[str, Callable],
    common_module_names: List[str],
    system_info_module_names: List[str],
    domain_controller_module_names: List[str],
    vulnerabilities_module_names: List[str],
) -> dict:
    if config.mode_name == "custom":
        module_names = config.custom_modules or list(all_modules.keys())
        for name in module_names:
            if name not in all_modules:
                raise ConfigError(f"Unknown module requested in custom mode: '{name}'")
        return custom.build_profile(
            module_names,
            threads=config.threads,
            connect_timeout=config.connect_timeout,
            read_timeout=config.read_timeout,
            retries=config.retries,
        )

    if config.mode_name not in MODE_REGISTRY:
        raise ConfigError(f"Unknown mode '{config.mode_name}'")

    profile = dict(MODE_REGISTRY[config.mode_name])

    if config.run_common or config.run_info or config.run_dc or config.run_vuln:
        selected_modules = []
        if config.run_common:
            selected_modules.extend(common_module_names)
        if config.run_info:
            for name in system_info_module_names:
                if name not in selected_modules:
                    selected_modules.append(name)
        if config.run_dc:
            for name in domain_controller_module_names:
                if name not in selected_modules:
                    selected_modules.append(name)
        if config.run_vuln:
            for name in vulnerabilities_module_names:
                if name not in selected_modules:
                    selected_modules.append(name)
        profile["modules"] = selected_modules

    return profile


class Engine:
    def __init__(self, config: EngineConfig):
        self.config = config
        self.logger = OxLogger.get()
        common_modules = discover_common_modules()
        system_info_modules = discover_system_info_modules()
        domain_controller_modules = discover_domain_controller_modules()
        vulnerabilities_modules = discover_vulnerabilities_modules()
        self.all_modules = {
            **common_modules,
            **system_info_modules,
            **domain_controller_modules,
            **vulnerabilities_modules,
        }
        self.profile = resolve_mode_profile(
            config,
            self.all_modules,
            list(common_modules.keys()),
            list(system_info_modules.keys()),
            list(domain_controller_modules.keys()),
            list(vulnerabilities_modules.keys()),
        )
        self.credentials = Credentials.from_args(
            username=config.username,
            password=config.password,
            ntlm_hash=config.ntlm_hash,
            domain=config.domain,
        )
        self.output = JSONOutputWriter(output_path=config.output_path)

    def _call_module(self, module_func: Callable, target: Target, auth_session):
        signature = inspect.signature(module_func)
        candidate_kwargs = {
            "host": target.host,
            "port": target.port,
            "connect_timeout": self.profile["connect_timeout"],
            "read_timeout": self.profile["read_timeout"],
            "credentials": self.credentials,
            "auth_session": auth_session,
        }
        accepted_kwargs = {
            key: value for key, value in candidate_kwargs.items() if key in signature.parameters
        }
        return module_func(**accepted_kwargs)

    def _run_module_with_retry(
        self, module_name: str, module_func: Callable, target: Target, auth_session
    ):
        last_result = None
        attempts = self.profile["retries"] + 1
        for attempt in range(attempts):
            try:
                last_result = self._call_module(module_func, target, auth_session)
                if last_result.get("status") == "ok":
                    return last_result
            except OxSMBError as exc:
                last_result = {
                    "module": module_name,
                    "target": target.host,
                    "status": "error",
                    "data": None,
                    "error": str(exc),
                }
            except Exception as exc:
                last_result = {
                    "module": module_name,
                    "target": target.host,
                    "status": "error",
                    "data": None,
                    "error": f"Unexpected error: {exc}",
                }
            if attempt < attempts - 1:
                time.sleep(0.5)
        return last_result

    def _run_target(self, target: Target) -> List[dict]:
        if self.profile["jitter_max"] > 0:
            delay = random.uniform(self.profile["jitter_min"], self.profile["jitter_max"])
            time.sleep(delay)

        self.logger.info(f"Starting enumeration", target=target.host)

        auth_session = None
        if self.credentials is not None and not self.credentials.is_anonymous:
            auth_session = establish_session(
                host=target.host,
                port=target.port,
                credentials=self.credentials,
                connect_timeout=self.profile["connect_timeout"],
                read_timeout=self.profile["read_timeout"],
            )
            if auth_session.authenticated:
                self.logger.info("Authenticated session established", target=target.host)
            else:
                self.logger.warning(
                    f"Shared authentication failed: {auth_session.error}", target=target.host
                )

        try:
            results = []
            for module_name in self.profile["modules"]:
                module_func = self.all_modules.get(module_name)
                if module_func is None:
                    results.append(
                        {
                            "module": module_name,
                            "target": target.host,
                            "status": "error",
                            "data": None,
                            "error": "Module not found",
                        }
                    )
                    continue

                result = self._run_module_with_retry(module_name, module_func, target, auth_session)

                if result.get("status") != "ok":
                    self.logger.warning(
                        f"{module_name} failed: {result.get('error')}", target=target.host
                    )

                results.append(result)
        finally:
            close_session(auth_session)

        failed_count = sum(1 for result in results if result.get("status") != "ok")
        if failed_count == 0:
            self.logger.success("Common Modules completed", target=target.host)
        else:
            self.logger.warning(
                f"Common Modules completed with {failed_count} failure(s)", target=target.host
            )

        self.output.add_result(target.host, results)
        return results

    def run(self, on_target_started: Callable = None, on_target_done: Callable = None) -> JSONOutputWriter:
        targets = build_target_list(self.config.targets, self.config.port)
        if not targets:
            raise ConfigError("No valid targets to scan")

        self.logger.info(
            f"Launching mode '{self.profile['name']}' against {len(targets)} target(s) "
            f"with {self.profile['threads']} thread(s)"
        )

        if on_target_started is not None:
            on_target_started(len(targets))

        with ThreadPoolExecutor(max_workers=max(1, self.profile["threads"])) as executor:
            futures = {executor.submit(self._run_target, target): target for target in targets}
            for future in as_completed(futures):
                target = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    self.logger.error(f"Unhandled error: {exc}", target=target.host)
                finally:
                    if on_target_done is not None:
                        on_target_done(target)

        return self.output
