"""Loading and validation of the pipeline configuration file.

The configuration is a JSON document that describes the virtual machine
layout to be modelled by the generated SLEIGH spec (virtual program counter,
virtual stack pointer, state regions and extra context variables) together
with the list of opcode handlers the pipeline should analyse.  Example::

    {
      "vpc": "VPC",
      "vsp": "VSP",
      "regions": [{"name": "ram", "kind": "state", "base": null, "size": null}],
      "context": [],
      "entry": 4198400,
      "handlers": [
        {"opcode": 16, "entry": 4198416, "end": 4198496, "mnemonic": "add"}
      ]
    }

``vpc`` and a non-empty ``handlers`` list are mandatory; every handler must
carry integer ``entry`` and ``end`` addresses (and an integer ``opcode``).
Region ``kind`` must be one of the :class:`vmspec.model.RegionKind` values
(``"code"``, ``"stack"``, ``"state"``, ``"context"``, ``"global"``).
``bytecode``, when present, is a hex-encoded string.  Only the standard
library is used.
"""

from __future__ import annotations

import json
from typing import Any

from .model import Handler, Region, RegionKind, VMState

__all__ = ["load_config"]


def load_config(path: str) -> tuple[VMState, list[Handler]]:
    """Load and validate a VMSpec pipeline configuration file.

    Args:
        path: Path of the JSON configuration file (see module docstring).

    Returns:
        A ``(VMState, list[Handler])`` pair ready to be fed to
        :func:`vmspec.pipeline.run_pipeline`.

    Raises:
        ValueError: If the file is not valid JSON, a required field is
            missing, or any field has the wrong type.
        OSError: If the file cannot be read.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw: Any = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"config file {path!r} is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError(
            f"config file {path!r} must contain a JSON object, "
            f"got {type(raw).__name__}"
        )

    vpc = raw.get("vpc")
    if not isinstance(vpc, str) or not vpc:
        raise ValueError(
            "config field 'vpc' (virtual program counter register) is "
            f"required and must be a non-empty string, got {vpc!r}"
        )

    vsp = raw.get("vsp")
    if vsp is not None and not isinstance(vsp, str):
        raise ValueError(
            "config field 'vsp' (virtual stack pointer register) must be "
            f"a string or null, got {vsp!r}"
        )

    vm_state = VMState(
        vpc=vpc,
        vsp=vsp,
        regions=_parse_regions(raw.get("regions", [])),
        context=_parse_context(raw.get("context", [])),
        entry=_parse_optional_int(raw.get("entry"), "entry"),
        bytecode=_parse_bytecode(raw.get("bytecode")),
    )
    return vm_state, _parse_handlers(raw)


def _parse_regions(raw_regions: Any) -> list[Region]:
    """Parse the ``regions`` array into :class:`Region` objects."""
    if not isinstance(raw_regions, list):
        raise ValueError(
            "config field 'regions' must be a list (or omitted), "
            f"got {type(raw_regions).__name__}"
        )
    regions: list[Region] = []
    for i, item in enumerate(raw_regions):
        where = f"regions[{i}]"
        if not isinstance(item, dict):
            raise ValueError(f"{where} must be a JSON object, got {type(item).__name__}")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(
                f"{where}.name is required and must be a non-empty string, got {name!r}"
            )
        where = f"regions[{i}] ({name!r})"
        kind = item.get("kind")
        try:
            region_kind = RegionKind(kind)
        except (TypeError, ValueError):
            valid = ", ".join(k.value for k in RegionKind)
            raise ValueError(
                f"{where}.kind must be one of: {valid}; got {kind!r}"
            ) from None
        regions.append(
            Region(
                name=name,
                kind=region_kind,
                base=_parse_optional_int(item.get("base"), f"{where}.base"),
                size=_parse_optional_int(item.get("size"), f"{where}.size"),
            )
        )
    return regions


def _parse_context(raw_context: Any) -> list[str]:
    """Parse the ``context`` array (identifiers of extra context variables)."""
    if not isinstance(raw_context, list):
        raise ValueError(
            "config field 'context' must be a list (or omitted), "
            f"got {type(raw_context).__name__}"
        )
    for i, name in enumerate(raw_context):
        if not isinstance(name, str) or not name:
            raise ValueError(f"context[{i}] must be a non-empty string, got {name!r}")
    return list(raw_context)


def _parse_bytecode(value: Any) -> bytes | None:
    """Parse the optional hex-encoded ``bytecode`` field."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(
            "config field 'bytecode' must be a hex-encoded string or null, "
            f"got {type(value).__name__}"
        )
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"config field 'bytecode' is not valid hex: {exc}") from exc


def _parse_optional_int(value: Any, where: str) -> int | None:
    """Parse a field that is either ``null`` or an integer."""
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"config field '{where}' must be an integer or null, got {value!r}")
    return value


def _parse_handlers(raw: Any) -> list[Handler]:
    """Parse and validate the ``handlers`` array."""
    raw_handlers = raw.get("handlers")
    if not isinstance(raw_handlers, list) or not raw_handlers:
        raise ValueError(
            "config field 'handlers' is required and must be a non-empty list "
            "of handler objects"
        )
    handlers: list[Handler] = []
    for i, item in enumerate(raw_handlers):
        where = f"handlers[{i}]"
        if not isinstance(item, dict):
            raise ValueError(f"{where} must be a JSON object, got {type(item).__name__}")
        fields: dict[str, int] = {}
        for key in ("opcode", "entry", "end"):
            value = item.get(key)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(
                    f"{where}.{key} is required and must be an integer, got {value!r}"
                )
            fields[key] = value
        mnemonic = item.get("mnemonic", "")
        if not isinstance(mnemonic, str):
            raise ValueError(f"{where}.mnemonic must be a string, got {mnemonic!r}")
        handlers.append(
            Handler(
                opcode=fields["opcode"],
                entry=fields["entry"],
                end=fields["end"],
                mnemonic=mnemonic,
            )
        )
    return handlers