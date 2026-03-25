"""Shared utility functions for Vigil."""


def nested_get(d: dict, dotted_key: str, default=None):
    """Safely navigate a nested dict with dot-separated keys."""
    keys = dotted_key.split(".")
    current = d
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k)
        else:
            return default
        if current is None:
            return default
    return current
