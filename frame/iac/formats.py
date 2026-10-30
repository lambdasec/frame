"""The names a policy's paths may start from, per infrastructure format."""

from __future__ import annotations


def view_names(language: str) -> set:
    if language == "kubernetes":
        from .kubernetes import view_names as kubernetes_views
        return kubernetes_views()
    return {"self"}


__all__ = ["view_names"]
