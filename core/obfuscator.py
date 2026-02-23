"""
SysWhispers4 - Obfuscation Utilities
Provides name randomization, stub ordering, and SSN encryption helpers.
"""
from __future__ import annotations
import random
import string
from typing import List


class Obfuscator:
    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)

    # -----------------------------------------------------------------------
    # Random identifier generation
    # -----------------------------------------------------------------------

    def random_prefix(self, length: int = 4) -> str:
        """Return a random alphabetic prefix to replace the default 'SW4_'."""
        return "".join(self._rng.choices(string.ascii_uppercase, k=1) +
                       self._rng.choices(string.ascii_letters, k=length - 1)) + "_"

    def random_name(self, base: str) -> str:
        """Replace a known prefix in base with a random one (for stub symbols)."""
        suffix = "".join(self._rng.choices(string.ascii_letters + string.digits, k=6))
        return f"_SW4_{suffix}_{base}"

    # -----------------------------------------------------------------------
    # Stub / function ordering randomization
    # -----------------------------------------------------------------------

    def shuffle_functions(self, functions: List[str]) -> List[str]:
        """Return a shuffled copy of the function list."""
        shuffled = list(functions)
        self._rng.shuffle(shuffled)
        return shuffled

    # -----------------------------------------------------------------------
    # SSN XOR encryption
    # -----------------------------------------------------------------------

    def generate_xor_key(self) -> int:
        """Generate a 32-bit XOR key for SSN encryption."""
        return self._rng.randint(0x01010101, 0xFEFEFEFE)

    @staticmethod
    def xor_ssn(ssn: int, key: int) -> int:
        """XOR-encrypt a single SSN with the given key."""
        return ssn ^ key

    @staticmethod
    def decrypt_c_macro(prefix: str, key: int) -> str:
        """Return a C preprocessor macro that decrypts an XOR'd SSN at runtime."""
        return (
            f"#define {prefix}DECRYPT_SSN(v) ((v) ^ 0x{key:08X}U)\n"
        )

    # -----------------------------------------------------------------------
    # Junk instruction insertion (for ASM stubs)
    # -----------------------------------------------------------------------

    def junk_nops(self, count: int | None = None) -> str:
        """Return a random sequence of harmless x64 instructions (MASM syntax)."""
        n = count if count is not None else self._rng.randint(1, 4)
        ops = [
            "nop",
            "xchg ax, ax",
            "lea r11, [r11]",
            f"mov r11d, 0{self._rng.randint(0, 0xFF):02X}h",
        ]
        return "\n    ".join(self._rng.choices(ops, k=n))

    # -----------------------------------------------------------------------
    # Egg value generation
    # -----------------------------------------------------------------------

    def generate_egg(self) -> int:
        """Return a random 64-bit egg value (used as placeholder for syscall)."""
        # Avoid 0x0F05 (syscall) sequences anywhere in the 8 bytes
        while True:
            v = self._rng.randint(0x0101010101010101, 0xFEFEFEFEFEFEFEFE)
            # Ensure the byte sequence doesn't accidentally contain 0F 05
            raw = v.to_bytes(8, "little")
            if b"\x0f\x05" not in raw:
                return v

    @staticmethod
    def egg_asm_bytes(egg: int) -> str:
        """Return MASM DB directive for the 8-byte egg."""
        b = list(egg.to_bytes(8, "little"))
        return "DB " + ", ".join(f"{x:02X}h" for x in b)
