"""
Library specifications for C and C++ programs.

This module defines ProcSpec for common C/C++ APIs including:
- Standard I/O (stdio.h)
- String functions (string.h)
- Memory functions (stdlib.h, malloc.h)
- Process/system functions (unistd.h, stdlib.h)
- File system operations
- Network (socket.h)
"""

from typing import Dict
from frame.sil.procedure import ProcSpec


def _source(kind: str, desc: str = "") -> ProcSpec:
    """Create a taint source spec"""
    return ProcSpec(is_source=kind, description=desc)


def _sink(kind: str, args: list = None, desc: str = "") -> ProcSpec:
    """Create a taint sink spec"""
    return ProcSpec(is_sink=kind, sink_args=args or [0], description=desc)


def _sanitizer(kinds: list, desc: str = "") -> ProcSpec:
    """Create a sanitizer spec"""
    return ProcSpec(is_sanitizer=kinds, description=desc)


def _propagator(args: list, desc: str = "") -> ProcSpec:
    """Create a taint propagator spec"""
    return ProcSpec(taint_propagates=args, description=desc)


# =============================================================================
# Standard I/O (stdio.h) - Taint Sources
# =============================================================================

STDIO_INPUT_SPECS = {
    # User input functions (taint sources)
    "gets": _source("user", "gets() - reads line from stdin (UNSAFE)"),
    "fgets": _source("user", "fgets() - reads line from stream"),
    "getchar": _source("user", "getchar() - reads char from stdin"),
    "getc": _source("user", "getc() - reads char from stream"),
    "fgetc": _source("user", "fgetc() - reads char from stream"),
    "scanf": _source("user", "scanf() - formatted input from stdin"),
    "fscanf": _source("user", "fscanf() - formatted input from stream"),
    "sscanf": _source("user", "sscanf() - formatted input from string"),
    "fread": _source("user", "fread() - reads from stream"),
    "getline": _source("user", "getline() - reads line from stream"),
    "getdelim": _source("user", "getdelim() - reads delimited from stream"),
    "read": _source("user", "read() - POSIX read from fd"),
    "pread": _source("user", "pread() - POSIX positional read"),

    # Environment (taint sources)
    "getenv": _source("env", "getenv() - environment variable"),
    "secure_getenv": _source("env", "secure_getenv() - secure environment variable"),

    # Command line (main arguments are sources)
    "argv": _source("user", "Command line arguments"),
}

# =============================================================================
# Standard I/O (stdio.h) - Output Sinks
# =============================================================================

STDIO_OUTPUT_SPECS = {
    # Format string sinks (format string vulnerability)
    "printf": _sink("format", [0], "printf() - format string sink"),
    "fprintf": _sink("format", [1], "fprintf() - format string sink"),
    "sprintf": _sink("format", [1], "sprintf() - format string sink (buffer overflow risk)"),
    "snprintf": _sink("format", [2], "snprintf() - format string sink"),
    "vprintf": _sink("format", [0], "vprintf() - format string sink"),
    "vfprintf": _sink("format", [1], "vfprintf() - format string sink"),
    "vsprintf": _sink("format", [1], "vsprintf() - format string sink"),
    "vsnprintf": _sink("format", [2], "vsnprintf() - format string sink"),
    "syslog": _sink("format", [1], "syslog() - format string sink"),

    # Output propagators
    "fputs": _propagator([0], "fputs() - writes string to stream"),
    "puts": _propagator([0], "puts() - writes string to stdout"),
    "fwrite": _propagator([0], "fwrite() - writes to stream"),
    "write": _propagator([0], "write() - POSIX write to fd"),
    "pwrite": _propagator([0], "pwrite() - POSIX positional write"),
}

# =============================================================================
# String Functions (string.h) - Buffer Overflow Risks
# =============================================================================

STRING_SPECS = {
    # Unsafe string functions (buffer overflow sinks)
    "strcpy": _sink("buffer", [1], "strcpy() - unsafe string copy (buffer overflow)"),
    "strcat": _sink("buffer", [1], "strcat() - unsafe string concat (buffer overflow)"),
    "strncpy": _propagator([1], "strncpy() - bounded string copy"),
    "strncat": _propagator([1], "strncat() - bounded string concat"),

    # String manipulation (propagators)
    "strlen": _propagator([0], "strlen() - string length"),
    "strcmp": _propagator([0, 1], "strcmp() - string compare"),
    "strncmp": _propagator([0, 1], "strncmp() - bounded string compare"),
    "strchr": _propagator([0], "strchr() - find char in string"),
    "strrchr": _propagator([0], "strrchr() - find last char in string"),
    "strstr": _propagator([0, 1], "strstr() - find substring"),
    "strdup": _propagator([0], "strdup() - duplicate string"),
    "strndup": _propagator([0], "strndup() - duplicate string with limit"),
    "strtok": _propagator([0], "strtok() - tokenize string"),
    "strtok_r": _propagator([0], "strtok_r() - reentrant tokenize"),

    # Memory functions (buffer sinks)
    "memcpy": _sink("buffer", [1], "memcpy() - memory copy (buffer overflow risk)"),
    "memmove": _sink("buffer", [1], "memmove() - memory move"),
    "memset": _propagator([0], "memset() - memory set"),
    "memcmp": _propagator([0, 1], "memcmp() - memory compare"),
    "bcopy": _sink("buffer", [0], "bcopy() - BSD memory copy (buffer overflow)"),
}

# =============================================================================
# Memory Allocation (stdlib.h, malloc.h)
# =============================================================================

MEMORY_SPECS = {
    # Allocation
    "malloc": _propagator([0], "malloc() - dynamic allocation"),
    "calloc": _propagator([0, 1], "calloc() - zeroed allocation"),
    "realloc": _propagator([0, 1], "realloc() - resize allocation"),
    "free": _propagator([0], "free() - deallocate"),

    # C++ allocation
    "new": _propagator([0], "new - C++ allocation"),
    "delete": _propagator([0], "delete - C++ deallocation"),
    "new[]": _propagator([0], "new[] - C++ array allocation"),
    "delete[]": _propagator([0], "delete[] - C++ array deallocation"),
}

# =============================================================================
# System/Process Functions (Command Injection Sinks)
# =============================================================================

SYSTEM_SPECS = {
    # Command execution (command injection sinks)
    "system": _sink("command", [0], "system() - command injection sink"),
    "popen": _sink("command", [0], "popen() - command injection sink"),
    "execl": _sink("command", [0], "execl() - command injection sink"),
    "execle": _sink("command", [0], "execle() - command injection sink"),
    "execlp": _sink("command", [0], "execlp() - command injection sink"),
    "execv": _sink("command", [0, 1], "execv() - command injection sink"),
    "execve": _sink("command", [0, 1], "execve() - command injection sink"),
    "execvp": _sink("command", [0, 1], "execvp() - command injection sink"),
    "execvpe": _sink("command", [0, 1], "execvpe() - command injection sink"),
    "fork": _propagator([0], "fork() - create process"),
    "vfork": _propagator([0], "vfork() - create process"),

    # Shell-like functions
    "wordexp": _sink("command", [0], "wordexp() - shell expansion"),
    "glob": _sink("path", [0], "glob() - path pattern expansion"),
}

# =============================================================================
# File Operations (Path Traversal Sinks)
# =============================================================================

FILE_SPECS = {
    # File open (path traversal sinks)
    "fopen": _sink("path", [0], "fopen() - file open (path traversal)"),
    "freopen": _sink("path", [0], "freopen() - file reopen (path traversal)"),
    "open": _sink("path", [0], "open() - POSIX open (path traversal)"),
    "openat": _sink("path", [1], "openat() - POSIX open relative (path traversal)"),
    "creat": _sink("path", [0], "creat() - create file (path traversal)"),

    # File manipulation
    "remove": _sink("path", [0], "remove() - delete file (path traversal)"),
    "rename": _sink("path", [0, 1], "rename() - rename file (path traversal)"),
    "unlink": _sink("path", [0], "unlink() - unlink file (path traversal)"),
    "rmdir": _sink("path", [0], "rmdir() - remove directory (path traversal)"),
    "mkdir": _sink("path", [0], "mkdir() - create directory (path traversal)"),
    "chdir": _sink("path", [0], "chdir() - change directory (path traversal)"),
    "chmod": _sink("path", [0], "chmod() - change permissions (path traversal)"),
    "chown": _sink("path", [0], "chown() - change owner (path traversal)"),
    "stat": _sink("path", [0], "stat() - file status (path traversal)"),
    "lstat": _sink("path", [0], "lstat() - link status (path traversal)"),
    "access": _sink("path", [0], "access() - check access (path traversal)"),
    "readlink": _sink("path", [0], "readlink() - read symlink (path traversal)"),
    "symlink": _sink("path", [0, 1], "symlink() - create symlink (path traversal)"),
    "link": _sink("path", [0, 1], "link() - create hard link (path traversal)"),

    # Directory operations
    "opendir": _sink("path", [0], "opendir() - open directory (path traversal)"),
    "readdir": _propagator([0], "readdir() - read directory entry"),
    "scandir": _sink("path", [0], "scandir() - scan directory (path traversal)"),

    # Path manipulation
    "realpath": _propagator([0], "realpath() - resolve path"),
    "basename": _propagator([0], "basename() - extract filename"),
    "dirname": _propagator([0], "dirname() - extract directory"),
}

# =============================================================================
# Network (socket.h) - SSRF/Network Sinks
# =============================================================================

NETWORK_SPECS = {
    # Socket creation
    "socket": _propagator([0, 1, 2], "socket() - create socket"),
    "connect": _sink("ssrf", [1], "connect() - connect socket (SSRF)"),
    "bind": _sink("ssrf", [1], "bind() - bind socket"),
    "listen": _propagator([0], "listen() - listen on socket"),
    "accept": _source("network", "accept() - accept connection"),

    # Socket I/O (taint sources/sinks)
    "recv": _source("network", "recv() - receive from socket"),
    "recvfrom": _source("network", "recvfrom() - receive with address"),
    "recvmsg": _source("network", "recvmsg() - receive message"),
    "send": _sink("network", [1], "send() - send to socket"),
    "sendto": _sink("network", [1], "sendto() - send with address"),
    "sendmsg": _sink("network", [1], "sendmsg() - send message"),

    # DNS (SSRF through hostname)
    "gethostbyname": _sink("ssrf", [0], "gethostbyname() - DNS lookup (SSRF)"),
    "gethostbyaddr": _sink("ssrf", [0], "gethostbyaddr() - reverse DNS"),
    "getaddrinfo": _sink("ssrf", [0], "getaddrinfo() - address lookup (SSRF)"),
    "getnameinfo": _propagator([0], "getnameinfo() - name lookup"),
}

# =============================================================================
# C++ Streams
# =============================================================================

CPP_STREAM_SPECS = {
    # Input streams (taint sources)
    "cin": _source("user", "std::cin - standard input"),
    "cin>>": _source("user", "std::cin >> - input operator"),
    "getline": _source("user", "std::getline() - read line"),
    "ifstream": _source("file", "std::ifstream - file input"),
    "ifstream.read": _source("file", "ifstream.read() - file input"),

    # Output streams (potential sinks for sensitive data)
    "cout": _propagator([0], "std::cout - standard output"),
    "cout<<": _propagator([0], "std::cout << - output operator"),
    "cerr": _propagator([0], "std::cerr - standard error"),
    "ofstream": _propagator([0], "std::ofstream - file output"),
}

# =============================================================================
# C++ String (std::string)
# =============================================================================

CPP_STRING_SPECS = {
    # String operations (propagators)
    "string::append": _propagator([0], "std::string::append"),
    "string::assign": _propagator([0], "std::string::assign"),
    "string::insert": _propagator([1], "std::string::insert"),
    "string::replace": _propagator([0, 2], "std::string::replace"),
    "string::substr": _propagator([0], "std::string::substr"),
    "string::c_str": _propagator([0], "std::string::c_str"),
    "string::data": _propagator([0], "std::string::data"),
    "string::copy": _propagator([0], "std::string::copy"),
    "string::find": _propagator([0, 1], "std::string::find"),

    # String conversion
    "to_string": _propagator([0], "std::to_string"),
    "stoi": _propagator([0], "std::stoi - string to int"),
    "stol": _propagator([0], "std::stol - string to long"),
    "stof": _propagator([0], "std::stof - string to float"),
    "stod": _propagator([0], "std::stod - string to double"),
    "atoi": _propagator([0], "atoi() - string to int"),
    "atol": _propagator([0], "atol() - string to long"),
    "atof": _propagator([0], "atof() - string to float"),
    "strtol": _propagator([0], "strtol() - string to long"),
    "strtoul": _propagator([0], "strtoul() - string to unsigned long"),
    "strtod": _propagator([0], "strtod() - string to double"),
}

# =============================================================================
# SQL (Embedded SQL, SQLite, MySQL C API)
# =============================================================================

SQL_SPECS = {
    # SQLite
    "sqlite3_exec": _sink("sql", [1], "sqlite3_exec() - SQL injection"),
    "sqlite3_prepare": _sink("sql", [1], "sqlite3_prepare() - SQL (usually safe)"),
    "sqlite3_prepare_v2": _sink("sql", [1], "sqlite3_prepare_v2() - SQL"),
    "sqlite3_bind_text": _sanitizer(["sql"], "sqlite3_bind_text() - parameterized"),
    "sqlite3_bind_int": _sanitizer(["sql"], "sqlite3_bind_int() - parameterized"),

    # MySQL C API
    "mysql_query": _sink("sql", [1], "mysql_query() - SQL injection"),
    "mysql_real_query": _sink("sql", [1], "mysql_real_query() - SQL injection"),
    "mysql_prepare": _propagator([1], "mysql_prepare() - prepared statement"),
    "mysql_stmt_bind_param": _sanitizer(["sql"], "mysql_stmt_bind_param() - parameterized"),
    "mysql_real_escape_string": _sanitizer(["sql"], "mysql_real_escape_string() - escape"),

    # PostgreSQL C API
    "PQexec": _sink("sql", [1], "PQexec() - SQL injection"),
    "PQexecParams": _propagator([1], "PQexecParams() - parameterized query"),
    "PQprepare": _propagator([2], "PQprepare() - prepared statement"),
    "PQescapeString": _sanitizer(["sql"], "PQescapeString() - escape"),
    "PQescapeLiteral": _sanitizer(["sql"], "PQescapeLiteral() - escape literal"),
}

# =============================================================================
# XML Parsing (XXE Vulnerabilities)
# =============================================================================

XML_SPECS = {
    # libxml2
    "xmlParseFile": _sink("xxe", [0], "xmlParseFile() - XXE vulnerability"),
    "xmlParseDoc": _sink("xxe", [0], "xmlParseDoc() - XXE vulnerability"),
    "xmlParseMemory": _sink("xxe", [0], "xmlParseMemory() - XXE vulnerability"),
    "xmlReadFile": _sink("xxe", [0], "xmlReadFile() - XXE vulnerability"),
    "xmlReadMemory": _sink("xxe", [0], "xmlReadMemory() - XXE vulnerability"),
    "xmlCtxtReadFile": _sink("xxe", [1], "xmlCtxtReadFile() - XXE vulnerability"),

    # Expat
    "XML_Parse": _sink("xxe", [1], "XML_Parse() - XXE vulnerability"),
    "XML_ParseBuffer": _sink("xxe", [0], "XML_ParseBuffer() - XXE"),
}

# =============================================================================
# Crypto (Weak Crypto Detection)
# =============================================================================

CRYPTO_SPECS = {
    # Weak hash functions
    "MD5": _propagator([0], "MD5 - weak hash (deprecated)"),
    "MD5_Init": _propagator([0], "MD5_Init - weak hash"),
    "MD5_Update": _propagator([0, 1], "MD5_Update - weak hash"),
    "MD5_Final": _propagator([0], "MD5_Final - weak hash"),
    "SHA1": _propagator([0], "SHA1 - weak hash (deprecated)"),
    "SHA1_Init": _propagator([0], "SHA1_Init - weak hash"),

    # DES (weak encryption)
    "DES_ecb_encrypt": _propagator([0], "DES_ecb_encrypt - weak encryption"),
    "DES_cbc_encrypt": _propagator([0], "DES_cbc_encrypt - weak encryption"),

    # Random (weak randomness)
    "rand": _propagator([0], "rand() - weak random (not cryptographically secure)"),
    "srand": _propagator([0], "srand() - seed weak random"),
    "random": _propagator([0], "random() - weak random"),
    "srandom": _propagator([0], "srandom() - seed random"),
}

# =============================================================================
# Sanitizers
# =============================================================================

SANITIZER_SPECS = {
    # Path sanitization
    "realpath": _sanitizer(["path"], "realpath() - canonicalize path"),
    "canonicalize_file_name": _sanitizer(["path"], "canonicalize_file_name()"),

    # Integer validation
    "abs": _propagator([0], "abs() - absolute value"),
    "labs": _propagator([0], "labs() - long absolute value"),
    "llabs": _propagator([0], "llabs() - long long absolute value"),
}

# =============================================================================
# Combined C/C++ Specs
# =============================================================================

C_SPECS: Dict[str, ProcSpec] = {}
C_SPECS.update(STDIO_INPUT_SPECS)
C_SPECS.update(STDIO_OUTPUT_SPECS)
C_SPECS.update(STRING_SPECS)
C_SPECS.update(MEMORY_SPECS)
C_SPECS.update(SYSTEM_SPECS)
C_SPECS.update(FILE_SPECS)
C_SPECS.update(NETWORK_SPECS)
C_SPECS.update(SQL_SPECS)
C_SPECS.update(XML_SPECS)
C_SPECS.update(CRYPTO_SPECS)
C_SPECS.update(SANITIZER_SPECS)

# C++ includes all C specs plus C++ specific
CPP_SPECS: Dict[str, ProcSpec] = {}
CPP_SPECS.update(C_SPECS)
CPP_SPECS.update(CPP_STREAM_SPECS)
CPP_SPECS.update(CPP_STRING_SPECS)
