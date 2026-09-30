from dataclasses import dataclass, field


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass
class Host:
    ip: str
    hostname: str | None = None
    ports: list[Port] = field(default_factory=list)