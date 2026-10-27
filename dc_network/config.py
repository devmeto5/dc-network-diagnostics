"""Validate explicit targets before any network activity."""

import ipaddress
import math
from pathlib import Path
import re
import tomllib


def host_name(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("host must be a hostname or IP literal")
    try:
        ipaddress.ip_address(value)
        if "%" in value:
            raise ValueError("Scoped IPv6 is not supported")
        return value
    except ValueError:
        labels = value.rstrip(".").split(".")
        if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", s) for s in labels):
            raise ValueError("Use an ASCII hostname or IP literal, not a URL, CIDR, or wildcard")
        return value


def validate(data, directory=Path(".")):
    if not isinstance(data, dict) or set(data) - {"timeout", "warning_days", "ca_file", "targets"}:
        raise ValueError("Unknown configuration key")
    timeout = data.get("timeout", 5)
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 1 <= timeout <= 30:
        raise ValueError("timeout must be a finite number from 1 to 30 seconds")
    days = data.get("warning_days", 30)
    if type(days) is not int or not 1 <= days <= 365:
        raise ValueError("warning_days must be an integer from 1 to 365")
    ca_file = data.get("ca_file")
    if ca_file is not None:
        if not isinstance(ca_file, str) or not ca_file:
            raise ValueError("ca_file must name a PEM trust bundle")
        ca_file = str((directory / ca_file).resolve())
        if not Path(ca_file).is_file():
            raise ValueError("ca_file does not exist")
    targets = data.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 32:
        raise ValueError("Provide 1 to 32 explicit targets")
    cleaned, seen = [], set()
    for target in targets:
        if not isinstance(target, dict) or set(target) - {"host", "port", "tls"}:
            raise ValueError("Invalid target fields")
        host = host_name(target.get("host"))
        port, tls = target.get("port"), target.get("tls", False)
        if type(port) is not int or not 1 <= port <= 65535 or type(tls) is not bool:
            raise ValueError("Each target needs port 1..65535 and a Boolean tls setting")
        key = (host.lower().rstrip("."), port)
        if key in seen:
            raise ValueError("Duplicate endpoint")
        seen.add(key)
        cleaned.append({"host": host, "port": port, "tls": tls})
    return {"timeout": timeout, "warning_days": days, "ca_file": ca_file, "targets": cleaned}


def load(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("Configuration exceeds 64 KiB")
    return validate(tomllib.loads(raw.decode("utf-8")), Path(path).resolve().parent)
