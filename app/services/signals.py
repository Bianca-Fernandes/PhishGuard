"""A single check result. Every module returns a list of these."""
from dataclasses import asdict, dataclass


@dataclass
class Signal:
    source: str      # url | ml | threat | domain
    name: str        # short title shown to the user
    status: str      # ok | info | warning | danger | unavailable
    points: int = 0  # how much this adds to the risk (0 = nothing)
    detail: str = ""  # plain-language reason

    def to_dict(self):
        return asdict(self)
