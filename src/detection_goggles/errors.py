"""Project-specific exceptions presented cleanly by the CLI."""


class DacError(Exception):
    """Base class for expected user-facing failures."""


class ContractError(DacError):
    """A pack, rule, evidence bundle, or detector violated its contract."""


class AcquisitionError(DacError):
    """No usable evidence could be acquired."""


class PackNotFoundError(DacError):
    """The requested Detection Pack could not be resolved."""
