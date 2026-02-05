"""Dynamic custom pin handler loader for OGM_slave_pi."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple
import hashlib
import importlib.util
import sys


def load_custom_handlers(
    custom_types_dir: Optional[str],
    *,
    built_in_handlers: Iterable[str],
    built_in_metrics: Iterable[str],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Load custom pin handler/metric maps from a directory of Python modules."""
    if not custom_types_dir:
        return {}, {}

    root = Path(custom_types_dir)
    if not root.exists():
        raise RuntimeError(f"Custom types directory does not exist: {root}")
    if not root.is_dir():
        raise RuntimeError(f"Custom types path is not a directory: {root}")

    handler_names = set(built_in_handlers)
    metric_names = set(built_in_metrics)
    custom_handlers: Dict[str, Any] = {}
    custom_metrics: Dict[str, Any] = {}

    module_paths = sorted(
        p for p in root.rglob("*.py") if "__pycache__" not in p.parts and not p.name.startswith("_")
    )
    for module_path in module_paths:
        module = _load_module(module_path)
        _merge_registry(
            custom_handlers,
            handler_names,
            getattr(module, "HANDLER_TYPES", {}),
            module_path,
            "handler",
        )
        _merge_registry(
            custom_metrics,
            metric_names,
            getattr(module, "METRIC_INPUT_REGS", {}),
            module_path,
            "metric",
        )
    return custom_handlers, custom_metrics


def _load_module(path: Path):
    digest = hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:10]
    module_name = f"ogm_pi_custom_{path.stem}_{digest}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load custom module spec: {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise RuntimeError(f"Failed to import custom module {path}: {exc}") from exc
    return module


def _merge_registry(
    destination: Dict[str, Any],
    used_names: set[str],
    source: Any,
    module_path: Path,
    registry_kind: str,
) -> None:
    if source is None:
        return
    if not isinstance(source, dict):
        raise RuntimeError(f"{module_path}: {registry_kind} registry must be a dict")

    for name, entry in source.items():
        if not isinstance(name, str) or not name:
            raise RuntimeError(f"{module_path}: {registry_kind} registry keys must be non-empty strings")
        if not callable(entry):
            raise RuntimeError(f"{module_path}: {registry_kind} '{name}' must be callable")
        if name in used_names:
            raise RuntimeError(f"{module_path}: duplicate {registry_kind} name '{name}'")
        used_names.add(name)
        destination[name] = entry
