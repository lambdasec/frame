"""A Dockerfile parser that reads files as BuildKit does: a port of
moby/buildkit frontend/dockerfile/parser (parser.go, line_parsers.go, split_command.go,
directives.go) and of the part of its shell lexer (shell/lex.go) that finds heredocs.

Ported line by line on purpose, as the apk version order was: a Dockerfile's meaning is what
BuildKit makes of it, quirks included (comments inside continuations are dropped, a line ending in
the escape character continues, `ENV a b` is the legacy form, a JSON array that is not one is a
shell command). `tests/iac_real/dockerfile` runs BuildKit's own parser on the same files and
`tests/test_iac_dockerfile.py` compares the two node for node.

`parse` returns the instructions in order. Each has the command as written, the builder flags
(`--from=build`), the arguments as BuildKit splits them (`args`; for ENV/LABEL triples of key,
value, separator), whether they were a JSON array, the first and last line, the heredocs, and for
ONBUILD the instruction it wraps.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


class DockerfileError(ValueError):
    """What BuildKit refuses to parse, with the line it names."""

    def __init__(self, message: str, line: int = 0):
        super().__init__(f"line {line}: {message}" if line else message)
        self.line = line


@dataclass
class Heredoc:
    name: str
    content: str = ""
    chomp: bool = False
    expand: bool = True
    fd: int = 0


@dataclass
class Instruction:
    cmd: str                                   # as written: FROM, run, Copy, ...
    args: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    json: bool = False
    start_line: int = 0
    end_line: int = 0
    original: str = ""
    heredocs: List[Heredoc] = field(default_factory=list)
    sub: Optional["Instruction"] = None        # ONBUILD's instruction

    @property
    def name(self) -> str:
        return self.cmd.lower()


_WHITESPACE = re.compile(r"[\t\v\f\r ]+")
_HEREDOC = re.compile(r"^(\d*)<<(-?)\s*([^<]*)$", re.S)
_DIRECTIVE = re.compile(r"^([a-zA-Z][a-zA-Z0-9]*)\s*=\s*(.+?)\s*$", re.S)
_VALID_DIRECTIVES = {"syntax", "escape", "check"}
_HEREDOC_COMMANDS = {"add", "copy", "run"}
_GO_SPACE = " \t\n\v\f\r\x85\xa0"          # unicode.IsSpace for the Latin-1 range


def _is_space(ch: str) -> bool:
    return ch in _GO_SPACE or (ord(ch) > 0xFF and ch.isspace())


def _lstrip(s: str) -> str:
    i = 0
    while i < len(s) and _is_space(s[i]):
        i += 1
    return s[i:]


class _Directives:
    def __init__(self):
        self.escape = "\\"
        self.continuation = None
        self.set_escape("\\")
        self.line = 0
        self.done = False
        self.seen: set = set()

    def set_escape(self, token: str) -> None:
        if token not in ("`", "\\"):
            raise DockerfileError(f"invalid escape token '{token}' does not match ` or \\")
        self.escape = token
        e = re.escape(token)
        self.continuation = re.compile(rf"([^{e}]){e}[ \t]*$|^{e}[ \t]*$")

    def parse_line(self, line: str) -> Optional[Tuple[str, str]]:
        """DirectiveParser.ParseLine: a `# key=value` line before anything else."""
        self.line += 1
        if self.done:
            return None
        if not line.startswith("#"):
            self.done = True
            return None
        m = _DIRECTIVE.match(_lstrip(line[1:]))
        if not m:
            self.done = True
            return None
        key = m.group(1).lower()
        if key not in _VALID_DIRECTIVES:
            self.done = True
            return None
        if key in self.seen:
            raise DockerfileError(f"only one {key} parser directive can be used")
        self.seen.add(key)
        return key, m.group(2)

    def possible_directive(self, line: str) -> bool:
        d = self.parse_line(line)
        if d is not None and d[0] == "escape":
            self.set_escape(d[1])
            return True
        return d is not None


def _is_comment(line: str) -> bool:
    s = _lstrip(line)
    return bool(s) and s[0] == "#"


def _trim_newline(s: str) -> str:
    return s.rstrip("\r\n")


def _process_line(d: _Directives, token: str, strip_left: bool) -> Tuple[str, bool]:
    token = _trim_newline(token)
    if strip_left:
        token = _lstrip(token)
    ok = d.possible_directive(token)
    return ("" if _is_comment(token) else token), ok


def _trim_continuation(line: str, d: _Directives) -> Tuple[str, bool]:
    if d.continuation.search(line):
        return d.continuation.sub(lambda m: m.group(1) or "", line, count=1), False
    return line, True


# --- splitting a command ------------------------------------------------------------------

def _split_command(line: str, d: _Directives) -> Tuple[str, List[str], str]:
    parts = _WHITESPACE.split(line.strip(" \t\n\v\f\r\x85\xa0"), maxsplit=1)
    flags: List[str] = []
    args = ""
    if len(parts) == 2:
        args, flags = _extract_flags(parts[1], d)
    return parts[0], flags, args.strip(" \t\n\v\f\r\x85\xa0")


def _extract_flags(line: str, d: _Directives) -> Tuple[str, List[str]]:
    """extractBuilderFlags: leading `--name=value` words. It walks bytes, as the Go does."""
    data = line.encode("utf-8")
    words: List[str] = []
    phase, quote, blank_ok = 0, 0, False         # 0 spaces, 1 word, 2 quote
    buf: List[str] = []
    pos, n = 0, len(data)
    while pos <= n:
        ch = data[pos] if pos != n else None
        if phase == 0:
            if pos == n:
                break
            if _is_space(chr(ch)):
                pos += 1
                continue
            if ch != 0x2D or pos + 1 == n or data[pos + 1] != 0x2D:
                return data[pos:].decode("utf-8", errors="surrogateescape"), words
            phase = 1
        if phase in (1, 2) and pos == n:
            word = "".join(buf)
            if word != "--" and (blank_ok or word):
                words.append(word)
            break
        if phase == 1:
            c = chr(ch)
            if _is_space(c):
                word = "".join(buf)
                phase = 0
                if word == "--":
                    return data[pos:].decode("utf-8", errors="surrogateescape"), words
                if blank_ok or word:
                    words.append(word)
                buf = []
                blank_ok = False
                pos += 1
                continue
            if c in ("'", '"'):
                quote = ch
                blank_ok = True
                phase = 2
                pos += 1
                continue
            if c == d.escape:
                if pos + 1 == n:
                    pos += 1
                    continue
                pos += 1
                ch = data[pos]
            buf.append(chr(ch))
            pos += 1
            continue
        if phase == 2:
            if ch == quote:
                phase = 1
                pos += 1
                continue
            if chr(ch) == d.escape:
                if pos + 1 == n:
                    phase = 1
                    pos += 1
                    continue
                pos += 1
                ch = data[pos]
            buf.append(chr(ch))
            pos += 1
    return "", words


def _parse_words(rest: str, d: _Directives) -> List[str]:
    """parseWords: whitespace-separated words, quotes kept, escapes kept."""
    words: List[str] = []
    phase, quote, blank_ok = 0, "", False
    buf: List[str] = []
    pos, n = 0, len(rest)
    while pos <= n:
        ch = rest[pos] if pos != n else ""
        if phase == 0:
            if pos == n:
                break
            if _is_space(ch):
                pos += 1
                continue
            phase = 1
        if phase in (1, 2) and pos == n:
            if blank_ok or buf:
                words.append("".join(buf))
            break
        if phase == 1:
            if _is_space(ch):
                phase = 0
                if blank_ok or buf:
                    words.append("".join(buf))
                buf = []
                blank_ok = False
                pos += 1
                continue
            if ch in ("'", '"'):
                quote = ch
                blank_ok = True
                phase = 2
            if ch == d.escape:
                if pos + 1 == n:
                    pos += 1
                    continue
                buf.append(ch)
                pos += 1
                ch = rest[pos]
            buf.append(ch)
            pos += 1
            continue
        if phase == 2:
            if ch == quote:
                phase = 1
            if ch == d.escape and quote != "'":
                if pos + 1 == n:
                    phase = 1
                    pos += 1
                    continue
                pos += 1
                buf.append(ch)
                ch = rest[pos]
            buf.append(ch)
            pos += 1
    return words


# --- argument parsers (line_parsers.go) ----------------------------------------------------

class _NotStrings(DockerfileError):
    pass


def _parse_json(rest: str) -> Optional[List[str]]:
    rest = _lstrip(rest)
    if not rest.startswith("["):
        return None
    def no_constants(name):
        raise ValueError(name)                 # Go's encoding/json has no NaN or Infinity
    try:
        value = json.loads(rest, parse_constant=no_constants)
    except (ValueError, RecursionError):
        return None
    if not isinstance(value, list):
        return None
    if not all(isinstance(v, str) for v in value):
        raise _NotStrings("when using JSON array syntax, arrays must be comprised of strings only")
    return value


def _maybe_json(rest: str) -> Tuple[List[str], bool]:
    if rest == "":
        return [], False
    j = _parse_json(rest)
    return (j, True) if j is not None else ([rest], False)


def _maybe_json_list(rest: str) -> Tuple[List[str], bool]:
    j = _parse_json(rest)
    if j is not None:
        return j, True
    return _whitespace_delimited(rest), False


def _whitespace_delimited(rest: str) -> List[str]:
    return [] if rest == "" else _WHITESPACE.split(rest)


def _name_val(rest: str, key: str, d: _Directives) -> List[str]:
    words = _parse_words(rest, d)
    if not words:
        return []
    if "=" not in words[0]:
        parts = _WHITESPACE.split(rest, maxsplit=1)
        if len(parts) < 2:
            raise DockerfileError(f"{key} must have two arguments")
        return [parts[0], parts[1], ""]
    out: List[str] = []
    for w in words:
        if "=" not in w:
            raise DockerfileError(f"Syntax error - can't find = in {json.dumps(w)}. Must be of the form: name=value")
        k, v = w.split("=", 1)
        out += [k, v, "="]
    return out


def _health(rest: str) -> Tuple[List[str], bool]:
    sep = 0
    while sep < len(rest) and not _is_space(rest[sep]):
        sep += 1
    nxt = sep
    while nxt < len(rest) and _is_space(rest[nxt]):
        nxt += 1
    if sep == 0:
        return [], False
    cmd, is_json = _maybe_json(rest[nxt:])
    return [rest[:sep]] + cmd, is_json


def _instruction(line: str, d: _Directives) -> Instruction:
    cmd, flags, args = _split_command(line, d)
    name = cmd.lower()
    ins = Instruction(cmd=cmd, flags=flags, original=line)
    if name in ("add", "copy", "volume"):
        ins.args, ins.json = _maybe_json_list(args)
    elif name in ("cmd", "entrypoint", "run", "shell"):
        ins.args, ins.json = _maybe_json(args)
    elif name == "arg":
        ins.args = _parse_words(args, d)
    elif name in ("env", "label"):
        ins.args = _name_val(args, "ENV" if name == "env" else "LABEL", d)
    elif name in ("expose", "from"):
        ins.args = _whitespace_delimited(args)
    elif name == "healthcheck":
        ins.args, ins.json = _health(args)
    elif name in ("maintainer", "stopsignal", "user", "workdir"):
        ins.args = [args] if args else []
    elif name == "onbuild":
        if args:
            ins.sub = _instruction(args, d)
    else:
        ins.args = [""]                        # not an instruction BuildKit knows (parseIgnore)
    return ins


def _can_contain_heredoc(ins: Instruction) -> bool:
    node = ins.sub if ins.name == "onbuild" and ins.sub is not None else ins
    return node.name in _HEREDOC_COMMANDS and not node.json


# --- the shell lexer, as far as heredocs need it (shell/lex.go) ------------------------------

class _ShellError(DockerfileError):
    pass


class _Lexer:
    """shell.Lex with an empty environment and SkipUnsetEnv: variables stay as written."""

    def __init__(self, text: str, raw_quotes: bool, raw_escapes: bool):
        self.s = text
        self.i = 0
        self.raw_quotes = raw_quotes
        self.raw_escapes = raw_escapes
        self.escape = "\\"
        self.wbuf: List[str] = []

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def next(self) -> str:
        if self.i >= len(self.s):
            return ""
        ch = self.s[self.i]
        self.i += 1
        return ch

    def words(self) -> List[str]:
        return self.stop_on("", self.raw_escapes, False)[1]

    def stop_on(self, stop: str, raw_escapes: bool, preserve: bool) -> Tuple[str, List[str]]:
        # The word buffer is the lexer's, shared with nested calls (`${X:-word}`), and each
        # call starts by emptying it, as shellWord.wordsBuffer does: a word that a nested
        # expansion interrupts loses what came before it (`<< ${X:-d}` is not a heredoc).
        saved = self.raw_escapes
        self.raw_escapes = raw_escapes
        buf = self.wbuf
        buf.clear()
        try:
            result: List[str] = []
            words: List[str] = []
            in_word = False

            def flush() -> None:
                nonlocal in_word
                if buf:
                    words.append("".join(buf))
                    buf.clear()
                    in_word = False

            def add_char(c: str) -> None:
                nonlocal in_word
                if _is_space(c) and in_word:
                    flush()
                elif not _is_space(c):
                    buf.append(c)
                    in_word = True

            def add_raw(text: str) -> None:
                nonlocal in_word
                buf.append(text)
                in_word = True

            while self.peek() != "":
                ch = self.peek()
                if stop and ch == stop:
                    self.next()
                    flush()
                    return "".join(result), words
                if ch in ("$", "<", "'", '"'):
                    tmp = {"$": self.dollar, "<": self.heredoc_start,
                           "'": lambda: self.single(preserve), '"': lambda: self.double(preserve)}[ch]()
                    result.append(tmp)
                    if ch == "$":
                        for c in tmp:
                            add_char(c)
                    else:
                        add_raw(tmp)
                    continue
                ch = self.next()
                if ch == self.escape:
                    if self.raw_escapes:
                        add_raw(ch)
                        result.append(ch)
                    ch = self.next()
                    if ch == "":
                        break
                    add_raw(ch)
                else:
                    add_char(ch)
                result.append(ch)
            if stop:
                raise _ShellError(f"unexpected end of statement while looking for matching {stop}")
            flush()
            return "".join(result), words
        finally:
            self.raw_escapes = saved

    def single(self, preserve: bool) -> str:
        out: List[str] = []
        ch = self.next()
        if self.raw_quotes:
            out.append(ch)
        while True:
            ch = self.next()
            if ch == "":
                raise _ShellError("unexpected end of statement while looking for matching single-quote")
            if ch == "'":
                if self.raw_quotes:
                    out.append(ch)
                return "".join(out)
            if preserve and ch == self.escape:
                out.append(ch)
            out.append(ch)

    def double(self, preserve: bool) -> str:
        out: List[str] = []
        ch = self.next()
        if self.raw_quotes:
            out.append(ch)
        while True:
            p = self.peek()
            if p == "":
                raise _ShellError("unexpected end of statement while looking for matching double-quote")
            if p == '"':
                ch = self.next()
                if self.raw_quotes:
                    out.append(ch)
                return "".join(out)
            if p == "$":
                out.append(self.dollar())
                continue
            ch = self.next()
            if ch == self.escape:
                q = self.peek()
                if q == "":
                    continue
                if q in ('"', "$", self.escape):
                    if self.raw_escapes:
                        out.append(ch)
                    ch = self.next()
                elif self.raw_escapes and (not self.raw_quotes or preserve):
                    out.append(ch)
            out.append(ch)

    def name(self) -> str:
        out: List[str] = []
        while self.peek() != "":
            ch = self.peek()
            if not out and ch.isdigit():
                while self.peek() != "" and self.peek().isdigit():
                    out.append(self.next())
                return "".join(out)
            if not out and ch in "@*#?-$!0":
                return self.next()
            if not (ch.isalpha() or ch.isdigit() or ch == "_"):
                break
            out.append(self.next())
        return "".join(out)

    def dollar(self) -> str:
        self.next()
        if self.peek() != "{":
            n = self.name()
            return "$" if n == "" else "$" + n
        self.next()
        if self.peek() == "":
            raise _ShellError("syntax error: missing '}'")
        if self.peek() in "{}:":
            raise _ShellError("syntax error: bad substitution")
        n = self.name()
        ch = self.next()
        chs = ch
        if ch == "}":
            return "${" + n + "}"
        if ch == ":":
            ch = self.next()
            chs += ch
            null_is_unset = True
        else:
            null_is_unset = False
        if null_is_unset or ch in ("+", "-", "?", "#", "%"):     # `:` falls through (Go)
            raw = ch in ("#", "%")
            if null_is_unset and raw:
                raise _ShellError(f"unsupported modifier ({chs}) in substitution")
            try:
                word, _ = self.stop_on("}", raw, raw)
            except _ShellError:
                if self.peek() == "":
                    raise _ShellError("syntax error: missing '}'") from None
                raise
            return "${" + n + chs + word + "}"
        if ch == "/":
            if self.peek() == "/":
                self.next()
            try:
                pattern, _ = self.stop_on("/", True, True)
            except _ShellError:
                if self.peek() == "":
                    raise _ShellError("syntax error: missing '/' in ${}") from None
                raise
            try:
                replacement, _ = self.stop_on("}", True, False)
            except _ShellError:
                if self.peek() == "":
                    raise _ShellError("syntax error: missing '}'") from None
                raise
            return "${" + n + "/" + pattern + "/" + replacement + "}"
        raise _ShellError(f"unsupported modifier ({chs}) in substitution")

    def heredoc_start(self) -> str:
        self.next()
        if self.peek() != "<":
            return "<"
        self.next()
        space: List[str] = []
        while self.peek() in (" ", "\t", "\r"):
            space.append(self.next())
        return "<<" + "".join(space)


def _heredoc_from(word: str) -> Optional[Heredoc]:
    m = _HEREDOC.match(word)
    if not m:
        return None
    fd = int(m.group(1)) if m.group(1) else 0
    chomp, rest = m.group(2) == "-", m.group(3)
    if not rest:
        return None
    words = _Lexer(rest, raw_quotes=False, raw_escapes=False).words()
    if len(words) != 1:
        return None
    raw = _Lexer(rest, raw_quotes=True, raw_escapes=False).words()
    if len(raw) != len(words):
        raise DockerfileError(f"internal lexing of heredoc produced inconsistent results: {rest}")
    w = words[0]
    expand = (w.count("'") + w.count('"')) == (raw[0].count("'") + raw[0].count('"'))
    return Heredoc(name=w, chomp=chomp, expand=expand, fd=fd)


def _heredocs_in(line: str) -> List[Heredoc]:
    try:
        words = _Lexer(line, raw_quotes=True, raw_escapes=True).words()
    except _ShellError:
        words = []                            # BuildKit ignores this error (`words, _ :=`)
    out = []
    for w in words:
        h = _heredoc_from(w)
        if h is not None:
            out.append(h)
    return out


# --- the file --------------------------------------------------------------------------------

def _lines(text: str) -> List[str]:
    """scanLines: lines with their endings."""
    out, start = [], 0
    while True:
        i = text.find("\n", start)
        if i < 0:
            if start < len(text):
                out.append(text[start:])
            return out
        out.append(text[start:i + 1])
        start = i + 1


def parse(text: str) -> Tuple[List[Instruction], str]:
    """The instructions of a Dockerfile and its escape token. Raises DockerfileError where
    BuildKit refuses the file."""
    d = _Directives()
    lines = _lines(text)
    out: List[Instruction] = []
    current = 0
    idx = 0
    if lines and lines[0].startswith("﻿"):
        lines[0] = lines[0][1:]
    while idx < len(lines):
        raw = lines[idx]
        idx += 1
        try:
            read, _ = _process_line(d, raw, True)
        except DockerfileError as e:
            raise DockerfileError(str(e), current) from None
        current += 1
        start = current
        read, end_of_line = _trim_continuation(read, d)
        if end_of_line and not read:
            continue
        buf = [read]
        while not end_of_line and idx < len(lines):
            nxt = lines[idx]
            idx += 1
            try:
                part, _ = _process_line(d, nxt, False)
            except DockerfileError as e:
                raise DockerfileError(str(e), current) from None
            current += 1
            if _is_comment(nxt):
                continue
            if not _lstrip(_trim_newline(part)):
                continue
            part, end_of_line = _trim_continuation(part, d)
            buf.append(part)
        line = "".join(buf)
        try:
            ins = _instruction(line, d)
        except DockerfileError as e:
            raise DockerfileError(str(e), start) from None
        if _can_contain_heredoc(ins) and "<<" in line:
            try:
                docs = _heredocs_in(line)
            except DockerfileError as e:
                raise DockerfileError(str(e), start) from None
            for h in docs:
                content: List[str] = []
                terminated = False
                while idx < len(lines):
                    body = lines[idx]
                    idx += 1
                    current += 1
                    candidate = _trim_newline(body)
                    if h.chomp:
                        candidate = candidate.lstrip("\t")
                    if candidate == h.name:
                        terminated = True
                        break
                    content.append(body)
                if not terminated:
                    raise DockerfileError("unterminated heredoc", start)
                h.content = "".join(content)
                ins.heredocs.append(h)
        ins.start_line, ins.end_line = start, current
        out.append(ins)
    if not out:
        raise DockerfileError("file with no instructions", current)
    return out, d.escape


__all__ = ["DockerfileError", "Heredoc", "Instruction", "parse"]
