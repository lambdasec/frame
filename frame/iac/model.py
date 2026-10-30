"""The resource model every infrastructure format is read into.

A `Resource` is one thing a configuration declares (a Kubernetes object, a Terraform resource,
a CloudFormation resource, a Dockerfile stage): its type, its document (plain values, plus
`engine.Unknown` for what the files do not give), the line of every value, and its views, the
names a policy's paths start from (`self`, Kubernetes `pod`, ...).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Union

from .engine import DocPath, Subject
from .yaml_doc import Lines, line_of


@dataclass
class Resource:
    format: str                      # kubernetes / terraform / cloudformation / dockerfile
    type: str                        # Kubernetes kind, Terraform resource type, ...
    name: str
    file: str                        # as found under the scanned directory (posix, relative)
    line: int
    document: Any
    lines: Lines
    views: Dict[str, Union[DocPath, List[DocPath]]]
    address: str                     # how a user names it: "Deployment/web", "aws_s3_bucket.logs"
    constraints: List[Any] = field(default_factory=list)
    related: Dict[str, List[Any]] = field(default_factory=dict)   # other resources, by type

    def subject(self) -> Subject:
        return Subject(self.document, self.views, self.constraints, self.related)

    def line_of(self, path: DocPath) -> int:
        return line_of(self.lines, path, self.line)


@dataclass
class ReadResult:
    resources: List[Resource] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)          # files that declared resources


def dotted(path: DocPath) -> str:
    """`spec.containers[0].securityContext` for a document path."""
    out = ""
    for s in path:
        if isinstance(s, int):
            out += f"[{s}]"
        elif s.replace("_", "").replace("-", "").isalnum():
            out += ("." if out else "") + s
        else:
            out += f'["{s}"]'
    return out


__all__ = ["ReadResult", "Resource", "dotted"]
