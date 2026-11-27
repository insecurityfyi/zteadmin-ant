"""API integrations. ``REGISTRY`` maps an integration kind to its class."""
from __future__ import annotations

from .base import Field, Integration, IntegrationError, Record
from .cato import Cato
from .cloudflare import Cloudflare
from .fortigate import FortiGate
from .meraki import Meraki
from .netskope import Netskope
from .panos import PanOS
from .pfsense import PfSense
from .prisma import PrismaAccess
from .proxmox import Proxmox
from .sonicwall import SonicWall
from .unifi import UniFi
from .vyos import VyOS
from .zscaler import Zscaler

REGISTRY: dict[str, type[Integration]] = {
    cls.kind: cls for cls in (Zscaler, Netskope, Cato, PrismaAccess, Cloudflare, Meraki, PanOS, FortiGate, SonicWall, PfSense, VyOS, UniFi, Proxmox)
}


def build(kind: str, config: dict, http=None) -> Integration:
    try:
        cls = REGISTRY[kind]
    except KeyError:
        raise IntegrationError(f"Unknown integration type {kind!r}") from None
    return cls(config, http=http)


__all__ = ["REGISTRY", "build", "Field", "Integration", "IntegrationError", "Record"]
