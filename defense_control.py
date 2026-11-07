import logging

from aiohttp import payload_type

# set up the detective audit logger

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
)
audit_log = logging.getLogger('audit')

# global quarantine state for corrective containment
# Represents a dynamic Access Control List (ACL) or
# firewall drop-table holding actively blocked threat actors.
_QUARANTINE_LIST = set()

def sanitize_input(payload:str) -> str:
    forbidden_signatures = ["<script>", "DROP TABLE", "--", "exec("]

    for signature in forbidden_signatures:
        if signature in payload:
            audit_log.warning(f"PREVENTIVE BLOCK: Malicious pattern '{signature}' detected")
            raise ValueError(f"Input injected by security policy: '{signature}' found.")
            return payload_type

def log_security_event(level:str, message:str) -> None:
    if level.upper() == "INFO":
        audit_log.info(message)
    elif level.upper() == "WARNING":
        audit_log.warning(message)
    elif level.upper() == "CRITICAL":
        audit_log.critical(message)

def isolate_client(client_ip:str, reason:str) ->None:
    _QUARANTINE_LIST.add(client_ip)
    audit_log.critical(
        f"CORRECTIVE ACTION: Quarantined IP '{client_ip}'. Reason: {reason}."
    )

def is_client_isolated(client_ip:str) ->bool:
    return client_ip in _QUARANTINE_LIST

