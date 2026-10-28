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
      "base_addr": "0x1AE1000",
      "arch": "x86",
      "handlers": [
        {"opcode": 16, "entry": 4198416, "end": 4198496, "mnemonic": "add"}
      ]
    }

``vpc`` and a non-empty ``handlers`` list are mandatory; every handler must
carry integer ``entry`` and ``end`` addresses (and an integer ``opcode``).
Region ``kind`` must be one of the :class:`vmspec.model.RegionKind` values
(``"code"``, ``"stack"``, ``"state"``, ``"context"``, ``"global"``).
``bytecode``, when present, is a hex-encoded string.

The optional ``base_addr`` field (an integer in decimal form or a hex string
like ``"0x1AE1000"``) requests raw-blob loading: the pipeline maps the binary
file as a byte blob at that address instead of letting angr detect the file
format.  ``arch`` (string, default ``"x86"``) names the angr architecture to
use in that mode.  Only the standard library is used.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .model import Handler, Region, RegionKind, VMState

__all__ = ["Config", "load_config"]


@dataclass
class Config:
    """Parsed pipeline configuration.

    Attributes:
        vm_state: Layout of the virtual machine state.
        handlers: Opcode handlers to analyse.
        base_addr: Base address at which to map the binary as a raw blob in
            angr (``None`` selects format-detecting binary loading).
        arch: angr architecture name used when loading a raw blob.
    """

    vm_state: VMState
    handlers: list[Handler]
    base_addr: int | None = None
    arch: str = "x86"


def load_config(path: str) -> Config:
    """Load and validate a VMSpec pipeline configuration file.

    Args:
        path: Path of the JSON configuration file (see module docstring).

    Returns:
        A :class:`Config` containing the :class:`VMState`, the handler list
        and the optional raw-blob loading parameters (``base_addr`` and
        ``arch``), ready to be fed to
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
    return Config(
        vm_state=vm_state,
        handlers=_parse_handlers(raw),
        base_addr=_parse_base_addr(raw.get("base_addr")),
        arch=_parse_arch(raw.get("arch")),
    )


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


def _parse_base_addr(value: Any) -> int | None:
    """Parse the optional raw-blob mapping address ``base_addr``.

    Accepted forms: ``null``, a positive decimal integer (e.g. ``28185088``)
    or a string parsable with ``int(x, 0)`` so both ``"0x1AE1000"`` and
    ``"28185088"`` are valid.
    """
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        address = value
    elif isinstance(value, str):
        try:
            address = int(value, 0)
        except ValueError as exc:
            raise ValueError(
                "config field 'base_addr' must be a decimal integer or a hex "
                f"(0x-prefixed) string, got {value!r}"
            ) from exc
    else:
        raise ValueError(
            "config field 'base_addr' must be a decimal integer, a hex string "
            f"or null, got {type(value).__name__}"
        )
    if address <= 0:
        raise ValueError(
            f"config field 'base_addr' must be a positive address, got {value!r}"
        )
    return address


def _parse_arch(value: Any) -> str:
    """Parse the optional angr architecture name (default ``"x86"``)."""
    if value is None:
        return "x86"
    if not isinstance(value, str) or not value:
        raise ValueError(
            "config field 'arch' must be a non-empty string (e.g. 'x86'), got "
            f"{value!r}"
        )
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