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
    """Create a taint propagator spec (propagates to return value)"""
    return ProcSpec(taint_propagates=args, description=desc)


def _dest_propagator(args: list, desc: str = "") -> ProcSpec:
    """Create a dest taint propagator (propagates to arg 0/destination)

    Used for functions like strncat(dest, src, n) where taint from src
    flows to dest, not just to return value.
    """
    return ProcSpec(taint_to_dest=args, description=desc)


def _allocator(desc: str = "", may_return_null: bool = True) -> ProcSpec:
    """Create a memory allocator spec (malloc, new, etc.)"""
    return ProcSpec(allocates=True, may_return_null=may_return_null, description=desc)


def _deallocator(desc: str = "") -> ProcSpec:
    """Create a memory deallocator spec (free, delete, etc.)"""
    return ProcSpec(frees=True, description=desc)


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
    "GETENV": _source("env", "GETENV macro - environment variable"),
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
    # Unsafe string functions (buffer overflow sinks + dest propagation)
    "strcpy": ProcSpec(is_sink="buffer", sink_args=[1], taint_to_dest=[1],
                       description="strcpy() - copies taint from src to dest"),
    "strcat": ProcSpec(is_sink="buffer", sink_args=[1], taint_to_dest=[1],
                       description="strcat() - copies taint from src to dest"),
    "strncpy": _dest_propagator([1], "strncpy() - bounded copy, taint to dest"),
    "strncat": _dest_propagator([1], "strncat() - bounded concat, taint to dest"),

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
    # C allocation functions (allocates=True, may_return_null=True)
    "malloc": _allocator("malloc() - dynamic allocation"),
    "calloc": _allocator("calloc() - zeroed allocation"),
    "realloc": _allocator("realloc() - resize allocation"),
    "strdup": _allocator("strdup() - string duplication"),
    "strndup": _allocator("strndup() - bounded string duplication"),
    "aligned_alloc": _allocator("aligned_alloc() - aligned allocation"),
    "memalign": _allocator("memalign() - aligned allocation"),
    "posix_memalign": _allocator("posix_memalign() - POSIX aligned allocation"),
    "valloc": _allocator("valloc() - page-aligned allocation"),
    "pvalloc": _allocator("pvalloc() - page-aligned allocation"),
    "alloca": _allocator("alloca() - stack allocation", may_return_null=False),

    # C deallocation (frees=True)
    "free": _deallocator("free() - deallocate heap memory"),

    # C++ allocation (allocates=True)
    "new": _allocator("new - C++ heap allocation", may_return_null=False),
    "new[]": _allocator("new[] - C++ array allocation", may_return_null=False),
    "operator new": _allocator("operator new - C++ allocation", may_return_null=False),
    "operator new[]": _allocator("operator new[] - C++ array allocation", may_return_null=False),

    # C++ deallocation (frees=True)
    "delete": _deallocator("delete - C++ deallocation"),
    "delete[]": _deallocator("delete[] - C++ array deallocation"),
    "operator delete": _deallocator("operator delete - C++ deallocation"),
    "operator delete[]": _deallocator("operator delete[] - C++ array deallocation"),
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
# A01: Broken Access Control (OWASP 2025)
# =============================================================================

ACCESS_CONTROL_SPECS = {
    # Privilege operations
    "setuid": _sink("privilege", [0], "setuid (privilege escalation CWE-269)"),
    "setgid": _sink("privilege", [0], "setgid (privilege escalation CWE-269)"),
    "seteuid": _sink("privilege", [0], "seteuid (privilege escalation CWE-269)"),
    "setegid": _sink("privilege", [0], "setegid (privilege escalation CWE-269)"),
    "setreuid": _sink("privilege", [0, 1], "setreuid (privilege escalation CWE-269)"),
    "setregid": _sink("privilege", [0, 1], "setregid (privilege escalation CWE-269)"),

    # File permissions
    "umask": _sink("config", [0], "umask setting (CWE-732)"),
    "fchmod": _sink("config", [0, 1], "fchmod (CWE-732)"),
    "fchown": _sink("config", [0, 1, 2], "fchown (CWE-732)"),

    # Chroot/jail
    "chroot": _sink("privilege", [0], "chroot jail (check for breakout CWE-243)"),
}

# =============================================================================
# A02: Security Misconfiguration (OWASP 2025)
# =============================================================================

MISCONFIGURATION_SPECS = {
    # Debug/verbose mode
    "NDEBUG": _propagator([0], "NDEBUG flag"),
    "assert": _sink("assertion", [0], "assert (disabled in release CWE-617)"),

    # Hardcoded credentials
    "password": _sink("hardcoded_cred", [0], "Potential hardcoded password (CWE-798)"),
    "passwd": _sink("hardcoded_cred", [0], "Potential hardcoded password (CWE-798)"),
    "secret": _sink("hardcoded_cred", [0], "Potential hardcoded secret (CWE-798)"),
    "api_key": _sink("hardcoded_cred", [0], "Potential hardcoded API key (CWE-798)"),
    "private_key": _sink("hardcoded_cred", [0], "Potential hardcoded key (CWE-798)"),

    # SSL/TLS issues
    "SSL_CTX_set_verify": _sink("ssl", [0, 1], "SSL verification config (CWE-295)"),
    "SSL_set_verify": _sink("ssl", [0, 1], "SSL verification config (CWE-295)"),
    "SSL_CTX_set_options": _sink("ssl", [0, 1], "SSL options (CWE-327)"),
    "OPENSSL_NO_SSL2": _propagator([0], "SSLv2 disabled"),
    "OPENSSL_NO_SSL3": _propagator([0], "SSLv3 disabled"),
}

# =============================================================================
# A04: Cryptographic Failures Enhanced (OWASP 2025)
# =============================================================================

CRYPTO_ENHANCED_SPECS = {
    # OpenSSL deprecated functions
    "EVP_des_ecb": _sink("weak_crypto", [0], "DES ECB (CWE-327)"),
    "EVP_des_cbc": _sink("weak_crypto", [0], "DES CBC (CWE-327)"),
    "EVP_rc4": _sink("weak_crypto", [0], "RC4 (CWE-327)"),
    "EVP_rc2_cbc": _sink("weak_crypto", [0], "RC2 (CWE-327)"),
    "EVP_bf_ecb": _sink("weak_crypto", [0], "Blowfish ECB (CWE-327)"),

    # ECB mode
    "EVP_aes_128_ecb": _sink("weak_crypto", [0], "AES-128 ECB (CWE-327)"),
    "EVP_aes_256_ecb": _sink("weak_crypto", [0], "AES-256 ECB (CWE-327)"),

    # Weak key derivation
    "crypt": _sink("weak_crypto", [0], "crypt() weak hash (CWE-328)"),
    "crypt_r": _sink("weak_crypto", [0], "crypt_r() weak hash (CWE-328)"),

    # Secure alternatives
    "RAND_bytes": _sanitizer(["random"], "Cryptographically secure random"),
    "getrandom": _sanitizer(["random"], "Cryptographically secure random"),
    "arc4random": _sanitizer(["random"], "Cryptographically secure random"),
    "arc4random_buf": _sanitizer(["random"], "Cryptographically secure random"),

    # Key sizes
    "RSA_generate_key": _sink("weak_crypto", [0], "RSA key generation (check size CWE-326)"),
    "DSA_generate_parameters": _sink("weak_crypto", [0], "DSA params (check size CWE-326)"),
}

# =============================================================================
# A07: Identification and Authentication Failures (OWASP 2025)
# =============================================================================

AUTH_SPECS = {
    # PAM authentication
    "pam_authenticate": _sink("auth", [0], "PAM authentication"),
    "pam_start": _sink("auth", [0], "PAM start"),
    "pam_end": _propagator([0], "PAM end"),

    # Password handling
    "getpass": _source("user", "getpass() password input"),
    "getpwnam": _propagator([0], "Get password entry by name"),
    "getpwuid": _propagator([0], "Get password entry by UID"),
    "getspnam": _propagator([0], "Get shadow password entry"),
}

# =============================================================================
# A10: Mishandling of Exceptional Conditions (OWASP 2025 - NEW)
# =============================================================================

EXCEPTION_SPECS = {
    # Signal handling
    "signal": _sink("exception", [0, 1], "Signal handler (CWE-479)"),
    "sigaction": _sink("exception", [0, 1], "Signal action (CWE-479)"),
    "raise": _sink("exception", [0], "Raise signal"),

    # Error handling
    "perror": _sink("info_disclosure", [0], "perror (may leak info CWE-209)"),
    "strerror": _propagator([0], "strerror (error message)"),
    "errno": _propagator([0], "errno value"),

    # Abort/exit
    "abort": _sink("exception", [0], "abort (CWE-705)"),
    "exit": _sink("exception", [0], "exit (CWE-705)"),
    "_exit": _sink("exception", [0], "_exit"),
    "quick_exit": _sink("exception", [0], "quick_exit"),

    # Longjmp (dangerous)
    "longjmp": _sink("exception", [0], "longjmp (CWE-843)"),
    "siglongjmp": _sink("exception", [0], "siglongjmp (CWE-843)"),
    "setjmp": _propagator([0], "setjmp"),
}

# =============================================================================
# Integer Overflow/Underflow (A05 related)
# =============================================================================

INTEGER_SPECS = {
    # Size calculations
    "sizeof": _propagator([0], "sizeof"),
    "malloc": _sink("integer_overflow", [0], "malloc size (check overflow CWE-190)"),
    "calloc": _sink("integer_overflow", [0, 1], "calloc size (check overflow CWE-190)"),
    "realloc": _sink("integer_overflow", [0, 1], "realloc size (check overflow CWE-190)"),

    # Array indexing
    "[]": _sink("buffer", [0], "Array access (check bounds CWE-129)"),

    # Arithmetic operations (track)
    "+": _propagator([0, 1], "Addition (potential overflow)"),
    "*": _propagator([0, 1], "Multiplication (potential overflow)"),
}

# =============================================================================
# Race Conditions (A01 related)
# =============================================================================

RACE_CONDITION_SPECS = {
    # TOCTOU vulnerabilities
    "access": _sink("race", [0], "access() TOCTOU (CWE-367)"),
    "stat": _sink("race", [0], "stat() TOCTOU (CWE-367)"),
    "lstat": _sink("race", [0], "lstat() TOCTOU (CWE-367)"),

    # File creation
    "mktemp": _sink("race", [0], "mktemp race condition (CWE-377)"),
    "tempnam": _sink("race", [0], "tempnam race condition (CWE-377)"),
    "tmpnam": _sink("race", [0], "tmpnam race condition (CWE-377)"),

    # Safe alternatives
    "mkstemp": _sanitizer(["race"], "mkstemp (safe temp file)"),
    "mkostemp": _sanitizer(["race"], "mkostemp (safe temp file)"),
    "mkdtemp": _sanitizer(["race"], "mkdtemp (safe temp dir)"),

    # Locking
    "flock": _propagator([0, 1], "flock file lock"),
    "lockf": _propagator([0, 1], "lockf file lock"),
    "fcntl": _propagator([0, 1, 2], "fcntl (F_SETLK)"),
}

# =============================================================================
# Use After Free / Double Free (A10 related)
# =============================================================================

# Note: These specs combine is_sink for taint tracking with allocates/frees flags
# for memory safety analysis. Both are needed for complete coverage.

MEMORY_SAFETY_SPECS = {
    # Free operations - mark as deallocators AND sinks for double-free/UAF detection
    "free": ProcSpec(
        frees=True,
        is_sink="memory",
        sink_args=[0],
        description="free (check for UAF/double-free CWE-416/CWE-415)"
    ),
    "delete": ProcSpec(
        frees=True,
        is_sink="memory",
        sink_args=[0],
        description="delete (check for UAF CWE-416)"
    ),
    "delete[]": ProcSpec(
        frees=True,
        is_sink="memory",
        sink_args=[0],
        description="delete[] (check for UAF CWE-416)"
    ),
    "operator delete": ProcSpec(
        frees=True,
        is_sink="memory",
        sink_args=[0],
        description="operator delete (C++ deallocation)"
    ),
    "operator delete[]": ProcSpec(
        frees=True,
        is_sink="memory",
        sink_args=[0],
        description="operator delete[] (C++ array deallocation)"
    ),

    # Allocation operations - mark as allocators AND sinks for tracking
    "malloc": ProcSpec(
        allocates=True,
        may_return_null=True,
        is_sink="memory",
        sink_args=[0],
        description="malloc (dynamic allocation, may return NULL)"
    ),
    "calloc": ProcSpec(
        allocates=True,
        may_return_null=True,
        description="calloc (zeroed allocation)"
    ),
    "realloc": ProcSpec(
        allocates=True,
        may_return_null=True,
        description="realloc (resize allocation)"
    ),
    "new": ProcSpec(
        allocates=True,
        may_return_null=False,
        description="new (C++ heap allocation)"
    ),
    "new[]": ProcSpec(
        allocates=True,
        may_return_null=False,
        description="new[] (C++ array allocation)"
    ),
    "operator new": ProcSpec(
        allocates=True,
        may_return_null=False,
        description="operator new (C++ allocation)"
    ),
    "operator new[]": ProcSpec(
        allocates=True,
        may_return_null=False,
        description="operator new[] (C++ array allocation)"
    ),
    "alloca": ProcSpec(
        allocates=True,
        may_return_null=False,
        is_sink="memory",
        sink_args=[0],
        description="alloca (stack allocation CWE-770)"
    ),
    "strdup": ProcSpec(
        allocates=True,
        may_return_null=True,
        description="strdup (string duplication)"
    ),
    "strndup": ProcSpec(
        allocates=True,
        may_return_null=True,
        description="strndup (bounded string duplication)"
    ),
}

# =============================================================================
# Format String (A05 related)
# =============================================================================

FORMAT_STRING_ENHANCED_SPECS = {
    # Format string sinks with user input
    "printf": _sink("format_string", [0], "printf format string (CWE-134)"),
    "fprintf": _sink("format_string", [1], "fprintf format string (CWE-134)"),
    "sprintf": _sink("format_string", [1], "sprintf format string (CWE-134)"),
    "snprintf": _sink("format_string", [2], "snprintf format string (CWE-134)"),
    "syslog": _sink("format_string", [1], "syslog format string (CWE-134)"),
    "err": _sink("format_string", [1], "err format string (CWE-134)"),
    "warn": _sink("format_string", [0], "warn format string (CWE-134)"),
    "setproctitle": _sink("format_string", [0], "setproctitle format string (CWE-134)"),
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
# OWASP 2025 enhanced coverage
C_SPECS.update(ACCESS_CONTROL_SPECS)
C_SPECS.update(MISCONFIGURATION_SPECS)
C_SPECS.update(CRYPTO_ENHANCED_SPECS)
C_SPECS.update(AUTH_SPECS)
C_SPECS.update(EXCEPTION_SPECS)
C_SPECS.update(INTEGER_SPECS)
C_SPECS.update(RACE_CONDITION_SPECS)
C_SPECS.update(MEMORY_SAFETY_SPECS)
C_SPECS.update(FORMAT_STRING_ENHANCED_SPECS)

# C++ includes all C specs plus C++ specific
CPP_SPECS: Dict[str, ProcSpec] = {}
CPP_SPECS.update(C_SPECS)
CPP_SPECS.update(CPP_STREAM_SPECS)
CPP_SPECS.update(CPP_STRING_SPECS)
