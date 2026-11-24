"""Translate a Cargo release version into Alpine's version syntax."""

import sys


# apk-tools compares suffix numbers as uint64 and the hex field after ~ as bytes.
MAX_SUFFIX_NUMBER = (1 << 64) - 1
NATIVE_SUFFIXES = ("alpha", "beta", "rc")
IDENTIFIER_CHARACTERS = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def prerelease_order_key(identifiers: list[str]) -> str:
    """Encode identifiers into a compact, lexically sortable hex field."""
    bits = []
    for identifier in identifiers:
        if identifier.isdecimal():
            # Numeric identifiers come first and have no leading zeroes.
            # The release version limit leaves fewer than 128 digits here.
            bits.append(f"0{len(identifier):07b}")
            bits.extend(f"{int(digit):04b}" for digit in identifier)
        else:
            bits.append("1")
            bits.extend(
                f"{IDENTIFIER_CHARACTERS.index(character) + 1:06b}"
                for character in identifier
            )
            bits.append("000000")

    key = "".join(bits)
    return "".join(
        f"{int(key[index : index + 4].ljust(4, '0'), 2):x}"
        for index in range(0, len(key), 4)
    )


def apk_version(version: str) -> str:
    """Keep stable and common native versions while preserving prerelease order."""
    base, separator, prerelease = version.partition("-")
    if not separator:
        return base

    identifiers = prerelease.split(".")
    first, *rest = identifiers
    if first in NATIVE_SUFFIXES and rest and rest[0].isdecimal():
        number = int(rest[0])
        if number <= MAX_SUFFIX_NUMBER:
            native = f"{base}_{first}{number}"
            if len(rest) == 1:
                return native
            return f"{native}~{prerelease_order_key(identifiers)}"

    # Place other versions between the native suffix ranges. A hex field before
    # any suffix number sorts first, and one after the maximum sorts last.
    suffix = NATIVE_SUFFIXES[0]
    number = ""
    for native_suffix in NATIVE_SUFFIXES:
        if first < native_suffix or (first == native_suffix and not rest):
            break
        suffix = native_suffix
        number = str(MAX_SUFFIX_NUMBER)

    return f"{base}_{suffix}{number}~{prerelease_order_key(identifiers)}"


if __name__ == "__main__":
    print(apk_version(sys.argv[1]))
