"""
Optional adapters that wrap external red team engines (Garak, PyRIT) as probe
sources for the Range.

These engines often require Python 3.10 to 3.12 and are not installed in the
main environment. Each adapter imports its engine lazily and raises a clear
IntegrationNotAvailable error with setup guidance if the engine is missing, so
importing this package never fails on its own.
"""
from .base import IntegrationNotAvailable, integration_status

__all__ = ["IntegrationNotAvailable", "integration_status"]
