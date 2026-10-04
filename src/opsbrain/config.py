"""Configuration: one trusted YAML file written by the operator.

Every model is `extra=forbid`: a misspelt key must fail instead of silently producing a more permissive
setup. Nothing Claude supplies ever becomes a host, a path or a command: tools only select among the
names defined here.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator, model_validator

from .auto.config import AutoConfig
from .models import Access, _Model

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_RULE = re.compile(r"^(\*|[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?)(:[A-Za-z0-9_.*/-]+)?$")

DEFAULT_CONFIG = Path("~/.opsbrain/config.yaml")

__all__ = ["Access", "Config", "ConfigError", "DEFAULT_CONFIG", "config_path", "load_config"]


class ConfigError(Exception):
    pass


class HostConfig(_Model):
    address: str
    user: str = "root"
    jump: str | None = None  # name of another host
    port: int = Field(default=22, ge=1, le=65535)
    sudo: bool = False
    tags: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)  # units that may be inspected / restarted
    kind: str = "linux"  # linux | routeros

    @field_validator("address", "user")
    @classmethod
    def _plain(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
            raise ValueError(f"invalid value: {value!r}")
        return value

    @field_validator("services")
    @classmethod
    def _units(cls, value: list[str]) -> list[str]:
        for unit in value:
            if not re.fullmatch(r"[A-Za-z0-9@_.:-]+", unit):
                raise ValueError(f"invalid unit name: {unit!r}")
        return value


class TofuStack(_Model):
    runner: str  # host name where tofu runs
    dir: str  # absolute directory on the runner
    env_file: str | None = None  # sourced on the runner before tofu (secrets stay there)
    binary: str = "tofu"
    source_dir: str | None = None  # repo-relative directory with the *.tf sources
    sync: bool = False  # copy *.tf from source_dir to the runner before `plan`

    @field_validator("dir", "env_file")
    @classmethod
    def _abs(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"/[A-Za-z0-9_./-]+", value):
            raise ValueError(f"must be an absolute plain path: {value!r}")
        return value


class AnsibleConfig(_Model):
    dir: str = "ansible"  # repo-relative
    playbook_bin: str = "ansible-playbook"
    playbooks_dir: str = "playbooks"
    playbooks: list[str] = Field(default_factory=list)  # empty = every *.yml in playbooks_dir
    require_limit_for_apply: bool = True
    ssh_auth_sock_from_launchctl: bool = False
    env: dict[str, str] = Field(default_factory=dict)


class K8sConfig(_Model):
    kubectl: str = "kubectl"
    kubeconfig: str | None = None
    context: str | None = None
    argocd_namespace: str = "argocd"
    restart_threshold: int = 5  # pods with more restarts are reported by `overview`


class NetworkConfig(_Model):
    router: str  # host name (kind: routeros)
    tracked_export: str | None = None  # repo-relative tracked `/export hide-sensitive`
    print_paths: list[str] = Field(default_factory=lambda: [
        "/ip address", "/ip route", "/ip firewall filter", "/ip firewall nat", "/interface", "/ip dhcp-server lease",
        "/system resource", "/tool netwatch"])


class ObserveConfig(_Model):
    prometheus_url: str | None = None
    loki_url: str | None = None
    http_checks: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = True


class DocsConfig(_Model):
    globs: list[str] = Field(default_factory=lambda: ["docs/**/*.md", "*.md", "tasks/**/*.md"])
    status_file: str | None = None  # "what is managed by what" summary
    memory_file: str | None = None  # append-only log; the last entry is the current state


class DriftConfig(_Model):
    tofu_stacks: list[str] = Field(default_factory=list)  # empty = all
    playbooks: list[str] = Field(default_factory=list)
    network: bool = True


class Limits(_Model):
    max_items: int = Field(default=20, ge=1, le=500)
    max_chars: int = Field(default=6000, ge=500, le=100_000)
    change_ttl_s: int = Field(default=3600, ge=60, le=86_400)
    artifact_retention_days: int = Field(default=14, ge=1, le=3650)
    default_wait_s: int = Field(default=45, ge=0, le=600)


class HttpConfig(_Model):
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)
    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1:*", "localhost:*", "host.docker.internal:*"])


class Config(_Model):
    name: str = "infra"
    repo: str  # local checkout of the infrastructure repository
    data_dir: str = "~/.opsbrain"
    remote_job_dir: str = "/tmp/opsbrain"  # noqa: S108 - created 0700 on the runner
    ignore_failed_units: list[str] = Field(default_factory=list)  # known-noisy units, e.g. openipmi.service
    hosts: dict[str, HostConfig] = Field(default_factory=dict)
    tofu: dict[str, TofuStack] = Field(default_factory=dict)
    ansible: AnsibleConfig | None = None
    k8s: K8sConfig | None = None
    network: NetworkConfig | None = None
    observe: ObserveConfig = Field(default_factory=ObserveConfig)
    docs: DocsConfig = Field(default_factory=DocsConfig)
    drift: DriftConfig = Field(default_factory=DriftConfig)
    policy: dict[str, Access] = Field(default_factory=dict)
    limits: Limits = Field(default_factory=Limits)
    http: HttpConfig = Field(default_factory=HttpConfig)
    auto: AutoConfig = Field(default_factory=AutoConfig)

    @model_validator(mode="after")
    def _check(self) -> Config:
        for name, host in self.hosts.items():
            if not NAME.fullmatch(name):
                raise ValueError(f"invalid host name: {name!r}")
            if host.jump is not None:
                if host.jump not in self.hosts:
                    raise ValueError(f"host {name!r}: unknown jump host {host.jump!r}")
                if self.hosts[host.jump].jump is not None:
                    raise ValueError(f"host {name!r}: jump host {host.jump!r} must be directly reachable")
        for name, stack in self.tofu.items():
            if not NAME.fullmatch(name):
                raise ValueError(f"invalid tofu stack name: {name!r}")
            if stack.runner not in self.hosts:
                raise ValueError(f"tofu stack {name!r}: unknown runner {stack.runner!r}")
            if stack.sync and not stack.source_dir:
                raise ValueError(f"tofu stack {name!r}: `sync` needs `source_dir`")
        if self.network is not None and self.network.router not in self.hosts:
            raise ValueError(f"network: unknown router host {self.network.router!r}")
        for rule in self.policy:
            if not _RULE.fullmatch(rule):
                raise ValueError(f"invalid policy rule: {rule!r}")
        for stack_name in self.drift.tofu_stacks:
            if stack_name not in self.tofu:
                raise ValueError(f"drift: unknown tofu stack {stack_name!r}")
        return self

    @property
    def repo_path(self) -> Path:
        return Path(self.repo).expanduser().resolve()

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir).expanduser().resolve()


def config_path(explicit: str | os.PathLike[str] | None = None) -> Path:
    raw = explicit or os.environ.get("OPSBRAIN_CONFIG") or DEFAULT_CONFIG
    return Path(raw).expanduser()


def load_config(explicit: str | os.PathLike[str] | None = None) -> Config:
    path = config_path(explicit)
    if not path.is_file():
        raise ConfigError(f"config not found: {path} (run `opsbrain init`)")
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return Config.model_validate(raw)
    except (yaml.YAMLError, ValueError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
