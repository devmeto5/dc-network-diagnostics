"""Process-level timeout covers blocking system DNS as well as sockets."""

import json
import subprocess
import sys

from .reporting import finding


def unavailable(target, reason):
    return {"host": target["host"], "port": target["port"], "checks": [
        finding(name, "UNKNOWN", reason, "Check local execution, resolver, and timeout; retry explicitly.")
        for name in ["dns", "tcp"] + (["tls"] if target["tls"] else [])]}


def run_target(target, config):
    payload = {"target": target, "timeout": config["timeout"],
               "warning_days": config["warning_days"], "ca_file": config["ca_file"]}
    try:
        process = subprocess.run([sys.executable, "-m", "dc_network.worker"],
                                 input=json.dumps(payload), text=True, capture_output=True,
                                 timeout=config["timeout"] + 1, check=False)
        if process.returncode:
            return unavailable(target, "Probe process failed")
        result = json.loads(process.stdout)
        if (result.get("host") != target["host"] or result.get("port") != target["port"]
                or not isinstance(result.get("checks"), list) or not result["checks"]):
            return unavailable(target, "Invalid probe response")
        return result
    except subprocess.TimeoutExpired:
        # subprocess.run kills and waits for the child on timeout.
        return unavailable(target, "Endpoint deadline exceeded; worker terminated")
    except (OSError, ValueError, AttributeError):
        return unavailable(target, "Probe response unavailable")


def collect(config):
    return [run_target(target, config) for target in config["targets"]]


def demo():
    return [{"host": "web.demo.invalid", "port": 443, "checks": [
        finding("dns", "OK", "Synthetic resolver returned one address"),
        finding("tcp", "OK", "Synthetic connection: 8.4 ms"),
        finding("tls", "WARNING", "Synthetic certificate expires in 14 days", "Schedule certificate renewal.")]},
        {"host": "backup.demo.invalid", "port": 22, "checks": [
        finding("dns", "OK", "Synthetic resolver returned one address"),
        finding("tcp", "CRITICAL", "Synthetic connection refused", "Inspect listener and firewall policy.")]}]
