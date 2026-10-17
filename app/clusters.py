import json
import os
import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


@dataclass(frozen=True)
class Cluster:
    name: str
    addr: str
    cacert: str = ""
    namespace: str = ""
    monitor_token: str = ""

    @property
    def verify(self) -> bool | str:
        return self.cacert or True


# The cluster chosen for the current request (or monitoring pass).
cluster_var: ContextVar[Cluster | None] = ContextVar("vault_cluster", default=None)


def _secret(entry: dict) -> str:
    """Monitoring token from an env var or a file (e.g. a Docker secret); never from the JSON itself."""
    if entry.get("monitor_token_env"):
        return os.environ.get(entry["monitor_token_env"], "").strip()
    if entry.get("monitor_token_file"):
        try:
            return Path(entry["monitor_token_file"]).read_text().strip()
        except OSError:
            return ""
    return ""


def load_clusters() -> list[Cluster]:
    """Clusters from VAULT_CLUSTERS_FILE (JSON list), else one cluster from VAULT_ADDR."""
    path = os.environ.get("VAULT_CLUSTERS_FILE")
    if not path:
        default = Cluster(
            name="default",
            addr=os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200").rstrip("/"),
            cacert=os.environ.get("VAULT_CACERT", ""),
            monitor_token=os.environ.get("VAULT_MONITOR_TOKEN", "").strip(),
        )
        return [default]
    entries = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(entries, list) or not entries:
        raise ValueError("VAULT_CLUSTERS_FILE must contain a non-empty JSON list")
    clusters, seen = [], set()
    for e in entries:
        name = str(e.get("name", ""))
        if not NAME_RE.match(name) or name in seen:
            raise ValueError(f"Invalid or duplicate cluster name: {name!r}")
        if not str(e.get("addr", "")).startswith(("http://", "https://")):
            raise ValueError(f"Cluster {name}: addr must start with http:// or https://")
        seen.add(name)
        clusters.append(Cluster(name=name, addr=e["addr"].rstrip("/"), cacert=e.get("cacert", ""),
                                namespace=e.get("namespace", "").strip("/"),
                                monitor_token=_secret(e)))
    return clusters


def get_cluster(name: str | None) -> Cluster | None:
    clusters = load_clusters()
    if not name:
        return clusters[0]
    return next((c for c in clusters if c.name == name), None)


@contextmanager
def use_cluster(cluster: Cluster):
    from vault import namespace_var

    t1, t2 = cluster_var.set(cluster), namespace_var.set(cluster.namespace)
    try:
        yield
    finally:
        namespace_var.reset(t2)
        cluster_var.reset(t1)
