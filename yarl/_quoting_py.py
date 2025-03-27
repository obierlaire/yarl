import codecs
import re
from string import ascii_letters, ascii_lowercase, digits
from typing import cast

BASCII_LOWERCASE = ascii_lowercase.encode("ascii")
BPCT_ALLOWED = {f"%{i:02X}".encode("ascii") for i in range(256)}
GEN_DELIMS = ":/?#[]@"
SUB_DELIMS_WITHOUT_QS = "!$'()*,"
SUB_DELIMS = SUB_DELIMS_WITHOUT_QS + "+&=;"
RESERVED = GEN_DELIMS + SUB_DELIMS
UNRESERVED = ascii_letters + digits + "-._~"
ALLOWED = UNRESERVED + SUB_DELIMS_WITHOUT_QS

# Pre-compute percent-encoded values for all possible bytes (0-255)
# This eliminates the need for string formatting and encoding in the hot path
PERCENT_ENCODED = [(f"%{i:02X}").encode("ascii") for i in range(256)]

_IS_HEX = re.compile(b"[A-Z0-9][A-Z0-9]")
_IS_HEX_STR = re.compile("[A-Fa-f0-9][A-Fa-f0-9]")

utf8_decoder = codecs.getincrementaldecoder("utf-8")


class _Quoter:
    def __init__(
        self,
        *,
        safe: str = "",
        protected: str = "",
        qs: bool = False,
        requote: bool = True,
    ) -> None:
        self._safe = safe
        self._protected = protected
        self._qs = qs
        self._requote = requote

        # Filter out non-ASCII characters for safe characters
        safe_chars = "".join(c for c in safe if ord(c) < 128) + ALLOWED
        if not qs:
            safe_chars += "+&=;"

        # Handle protected characters - we need to handle non-ASCII characters
        protected_ascii = "".join(c for c in protected if ord(c) < 128)
        safe_chars += protected_ascii

        # Convert to bytes for fast checks
        self._bsafe = safe_chars.encode("ascii")
        # Store protected as bytes separately to handle non-ASCII characters
        self._bprotected = protected_ascii.encode("ascii")

        # Track non-ASCII protected characters separately
        self._non_ascii_protected = {ord(c) for c in protected if ord(c) >= 128}

    def __call__(self, val: str) -> str:
        if val is None:
            return None
        if not isinstance(val, str):
            raise TypeError("Argument should be str")
        if not val:
            return ""

        bval = val.encode("utf8", errors="ignore")
        ret = bytearray()
        pct = bytearray()
        bsafe = self._bsafe
        bprotected = self._bprotected
        non_ascii_protected = self._non_ascii_protected
        idx = 0
        blen = len(bval)

        while idx < blen:
            ch = bval[idx]
            idx += 1

            if pct:
                if ch in BASCII_LOWERCASE:
                    ch = ch - 32  # convert to uppercase
                pct.append(ch)
                if len(pct) == 3:  # All 3 bytes of percent encoding are present
                    buf = pct[1:]
                    if not _IS_HEX.match(buf):
                        ret.extend(b"%25")
                        pct.clear()
                        idx -= 2
                        continue

                    # Initialize code_point and code_point_in_protected
                    code_point = 0
                    code_point_in_protected = False

                    try:
                        code_point = int(pct[1:].decode("ascii"), base=16)
                        if code_point < 128:
                            unquoted = chr(code_point)
                            code_point_in_protected = False
                        else:
                            # Handle multi-byte sequences - this needs special care
                            unquoted = None
                            code_point_in_protected = code_point in non_ascii_protected
                    except ValueError:
                        ret.extend(b"%25")
                        pct.clear()
                        idx -= 2
                        continue

                    if unquoted is not None and chr(code_point).encode('ascii', errors='ignore') in bprotected:
                        ret.extend(pct)
                    elif unquoted is not None and chr(code_point).encode('ascii', errors='ignore')[0] in bsafe:
                        ret.append(code_point)
                    elif code_point_in_protected:
                        # Non-ASCII protected character
                        ret.extend(pct)
                    else:
                        ret.extend(pct)
                    pct.clear()

                # special case, if we have only one char after "%"
                elif len(pct) == 2 and idx == blen:
                    ret.extend(b"%25")
                    pct.clear()
                    idx -= 1

                continue

            elif ch == ord("%") and self._requote:
                pct.clear()
                pct.append(ch)

                # special case if "%" is last char
                if idx == blen:
                    ret.extend(b"%25")

                continue

            if self._qs and ch == ord(" "):
                ret.append(ord("+"))
                continue

            # Fast path - use direct membership test
            if ch in bsafe:
                ret.append(ch)
                continue

            # Use pre-computed percent-encoded values
            ret.extend(PERCENT_ENCODED[ch])

        # Only decode if necessary
        if not ret:
            return ""

        ret2 = ret.decode("ascii")
        if ret2 == val:
            return val
        return ret2


class _Unquoter:
    def __init__(self, *, ignore: str = "", unsafe: str = "", qs: bool = False) -> None:
        self._ignore = ignore
        self._unsafe = unsafe
        self._qs = qs
        self._quoter = _Quoter()
        self._qs_quoter = _Quoter(qs=True)

        # Pre-compute sets for faster membership testing
        self._ignore_set = set(ignore)
        self._unsafe_set = set(unsafe)
        self._qs_special_set = set("+=&;")

    def __call__(self, val: str) -> str:
        if val is None:
            return None
        if not isinstance(val, str):
            raise TypeError("Argument should be str")
        if not val:
            return ""

        # Fast path - if no unsafe chars and no % or +, return as is
        if not self._unsafe and "%" not in val and (not self._qs or "+" not in val):
            return val

        decoder = cast(codecs.BufferedIncrementalDecoder, utf8_decoder())
        ret = []
        idx = 0
        val_len = len(val)
        unsafe_set = self._unsafe_set
        ignore_set = self._ignore_set

        while idx < val_len:
            ch = val[idx]
            idx += 1

            if ch == "%" and idx <= val_len - 2:
                pct = val[idx:idx + 2]
                if _IS_HEX_STR.fullmatch(pct):
                    b = bytes([int(pct, base=16)])
                    idx += 2
                    try:
                        unquoted = decoder.decode(b)
                    except UnicodeDecodeError:
                        start_pct = idx - 3 - len(decoder.buffer) * 3
                        ret.append(val[start_pct:idx - 3])
                        decoder.reset()
                        try:
                            unquoted = decoder.decode(b)
                        except UnicodeDecodeError:
                            ret.append(val[idx - 3:idx])
                            continue
                    if not unquoted:
                        continue

                    # Check if in special character sets
                    if self._qs and unquoted in self._qs_special_set:
                        to_add = self._qs_quoter(unquoted)
                        if to_add is None:  # pragma: no cover
                            raise RuntimeError("Cannot quote None")
                        ret.append(to_add)
                    elif unquoted in unsafe_set or unquoted in ignore_set:
                        to_add = self._quoter(unquoted)
                        if to_add is None:  # pragma: no cover
                            raise RuntimeError("Cannot quote None")
                        ret.append(to_add)
                    else:
                        ret.append(unquoted)
                    continue

            if decoder.buffer:
                start_pct = idx - 1 - len(decoder.buffer) * 3
                ret.append(val[start_pct:idx - 1])
                decoder.reset()

            if ch == "+":
                if not self._qs or ch in unsafe_set:
                    ret.append("+")
                else:
                    ret.append(" ")
                continue

            # Critical fix: Check if character is in unsafe set
            if ch in unsafe_set:
                # Format the character as percent-encoded
                ch_ord = ord(ch)
                hex_val = f"%{ch_ord:02X}"
                ret.append(hex_val)
                continue

            ret.append(ch)

        if decoder.buffer:
            ret.append(val[-len(decoder.buffer) * 3:])

        # Join the result
        result = "".join(ret)
        if result == val:
            return val
        return result
