"""The C/C++ integer model the range checks (CWE-190/191/194/195/197) reason with: the widths of
the integer types whose width the standard or the common ABIs fix, and the values of the
<limits.h> / <stdint.h> constants under that model. `long` and `size_t` (32 or 64 bits by
platform) are deliberately absent: arithmetic in them is not checked rather than guessed."""

from typing import Dict, Tuple

# declared type as written -> (bits, signed); plain `char` is signed, as on x86 and most ABIs
INT_TYPES: Dict[str, Tuple[int, bool]] = {
    "char": (8, True), "signed char": (8, True), "int8_t": (8, True),
    "unsigned char": (8, False), "uint8_t": (8, False),
    "short": (16, True), "short int": (16, True), "signed short": (16, True), "int16_t": (16, True),
    "unsigned short": (16, False), "unsigned short int": (16, False), "uint16_t": (16, False),
    "int": (32, True), "signed": (32, True), "signed int": (32, True), "int32_t": (32, True),
    "unsigned": (32, False), "unsigned int": (32, False), "uint32_t": (32, False),
    "long long": (64, True), "long long int": (64, True), "signed long long": (64, True),
    "int64_t": (64, True),
    "unsigned long long": (64, False), "unsigned long long int": (64, False), "uint64_t": (64, False),
}


def int_range(bits: int, signed: bool) -> Tuple[int, int]:
    return (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)


def _limits() -> Dict[str, int]:
    out: Dict[str, int] = {}
    for prefix, bits in (("SCHAR", 8), ("CHAR", 8), ("SHRT", 16), ("INT", 32), ("LLONG", 64)):
        out[prefix + "_MIN"], out[prefix + "_MAX"] = int_range(bits, True)
    for name, bits in (("UCHAR_MAX", 8), ("USHRT_MAX", 16), ("UINT_MAX", 32), ("ULLONG_MAX", 64)):
        out[name] = int_range(bits, False)[1]
    for bits in (8, 16, 32, 64):
        out[f"INT{bits}_MIN"], out[f"INT{bits}_MAX"] = int_range(bits, True)
        out[f"UINT{bits}_MAX"] = int_range(bits, False)[1]
    return out


LIMITS: Dict[str, int] = _limits()

__all__ = ["INT_TYPES", "LIMITS", "int_range"]
