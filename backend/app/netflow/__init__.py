"""NetFlow / IPFIX / sFlow ingest.

The point of this package is that a customer should not have to install
anything. Almost every managed switch, router and firewall already exports
flow records; pointing that export at SENTRY turns a two-hour agent rollout
into a two-line config change on hardware they already own.
"""

from .collector import FlowCollector, get_collector, set_collector
from .parser import FlowRecord, ParseResult, TemplateCache, parse_packet

__all__ = [
    "FlowCollector",
    "FlowRecord",
    "ParseResult",
    "TemplateCache",
    "get_collector",
    "parse_packet",
    "set_collector",
]
