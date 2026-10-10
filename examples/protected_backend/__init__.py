"""The integration: the guard in front of the translator.

C27 built a translator with no guard. This puts the gateway's decision in
control of whether that translator is ever invoked, and on exactly what text.
"""

from examples.protected_backend.backend import (
    Outcome,
    ProtectedTranslator,
    ScanTicket,
    TicketMismatch,
)

__all__ = ["Outcome", "ProtectedTranslator", "ScanTicket", "TicketMismatch"]
