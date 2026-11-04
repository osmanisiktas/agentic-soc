from collections import defaultdict
from datetime import timedelta

from app.models.alert import Alert
from app.models.event import (
    SecurityEvent,
    EventCategory,
    Severity,
)


RULE_ID = "BRUTE_FORCE_001"
THRESHOLD = 5
WINDOW_MINUTES = 5

FAILED_EVENT_NAMES = {
    "ssh_login_failed",
    "logon_failure",
    "login_failed",
    "authentication_failure",
}


def is_failed_authentication(event: SecurityEvent) -> bool:
    if event.category != EventCategory.AUTHENTICATION:
        return False

    if event.event_name.lower() in FAILED_EVENT_NAMES:
        return True

    raw_event_id = event.raw_event.get("event_id")
    return event.source.value == "windows" and raw_event_id == 4625


def get_source_ip(event: SecurityEvent) -> str | None:
    if event.network and event.network.source_ip:
        return event.network.source_ip

    raw_source_ip = event.raw_event.get("source_ip")
    if isinstance(raw_source_ip, str):
        return raw_source_ip

    return None


def detect_brute_force(
    events: list[SecurityEvent],
) -> list[Alert]:

    grouped_events = defaultdict(list)

    for event in events:
        if not is_failed_authentication(event):
            continue

        username = event.actor.username if event.actor else None
        source_ip = get_source_ip(event)

        if not username:
            continue

        grouped_events[(username, source_ip)].append(event)

    alerts = []

    for (username, source_ip), user_events in grouped_events.items():
        user_events.sort(key=lambda event: event.timestamp)

        left = 0

        for right, current_event in enumerate(user_events):
            while (
                current_event.timestamp - user_events[left].timestamp
                > timedelta(minutes=WINDOW_MINUTES)
            ):
                left += 1

            matching_events = user_events[left:right + 1]

            if len(matching_events) >= THRESHOLD:
                alerts.append(
                    Alert(
                        rule_id=RULE_ID,
                        title="Potential Brute Force Attack",
                        description=(
                            f"{len(matching_events)} failed authentication "
                            f"attempts for user '{username}' within "
                            f"{WINDOW_MINUTES} minutes."
                        ),
                        severity=Severity.HIGH,
                        username=username,
                        source_ip=source_ip,
                        event_ids=[
                            event.event_id for event in matching_events
                        ],
                        evidence={
                            "failed_attempts": len(matching_events),
                            "threshold": THRESHOLD,
                            "window_minutes": WINDOW_MINUTES,
                            "first_seen": matching_events[0].timestamp.isoformat(),
                            "last_seen": current_event.timestamp.isoformat(),
                        },
                    )
                )

                # Generate an alert on the first match. Do not generate
                # additional alerts for subsequent events in the same group.
                break

    return alerts
