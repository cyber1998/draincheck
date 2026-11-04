# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Draincheck Authors
"""Ways a payload can be obfuscated before the agent reads it.

Each encoding hides the instruction from a naive text filter while a language model can
still recover it. ``encode`` is what a scenario's payload is rendered with.
"""

from __future__ import annotations

import base64
import re

# ITU-R M.1677 Morse code for letters, digits and the punctuation a payload may use.
MORSE: dict[str, str] = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    ".": ".-.-.-",
    ",": "--..--",
    "?": "..--..",
    "'": ".----.",
    "!": "-.-.--",
    "/": "-..-.",
    "(": "-.--.",
    ")": "-.--.-",
    "&": ".-...",
    ":": "---...",
    ";": "-.-.-.",
    "=": "-...-",
    "+": ".-.-.",
    "-": "-....-",
    "_": "..--.-",
    '"': ".-..-.",
    "$": "...-..-",
    "@": ".--.-.",
}

# Latin letters -> Cyrillic look-alikes that render the same in most fonts.
HOMOGLYPHS: dict[str, str] = {
    "a": "\u0430",  # CYRILLIC SMALL LETTER A
    "c": "\u0441",  # CYRILLIC SMALL LETTER ES
    "e": "\u0435",  # CYRILLIC SMALL LETTER IE
    "o": "\u043e",  # CYRILLIC SMALL LETTER O
    "p": "\u0440",  # CYRILLIC SMALL LETTER ER
    "x": "\u0445",  # CYRILLIC SMALL LETTER HA
    "y": "\u0443",  # CYRILLIC SMALL LETTER U
    "i": "\u0456",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "s": "\u0455",  # CYRILLIC SMALL LETTER DZE
    "A": "\u0410",  # CYRILLIC CAPITAL LETTER A
    "B": "\u0412",  # CYRILLIC CAPITAL LETTER VE
    "C": "\u0421",  # CYRILLIC CAPITAL LETTER ES
    "E": "\u0415",  # CYRILLIC CAPITAL LETTER IE
    "H": "\u041d",  # CYRILLIC CAPITAL LETTER EN
    "K": "\u041a",  # CYRILLIC CAPITAL LETTER KA
    "M": "\u041c",  # CYRILLIC CAPITAL LETTER EM
    "O": "\u041e",  # CYRILLIC CAPITAL LETTER O
    "P": "\u0420",  # CYRILLIC CAPITAL LETTER ER
    "T": "\u0422",  # CYRILLIC CAPITAL LETTER TE
    "X": "\u0425",  # CYRILLIC CAPITAL LETTER HA
}

_WORD = re.compile(r"\S+")


def to_morse(text: str) -> str:
    """Morse code for `text`: letters separated by one space, words by " / "."""
    words = []
    for word in text.split():
        letters = []
        for char in word.upper():
            code = MORSE.get(char)
            if code is None:
                raise ValueError(f"no Morse code for {char!r} in {text!r}")
            letters.append(code)
        words.append(" ".join(letters))
    return " / ".join(words)


def to_homoglyphs(text: str) -> str:
    """Swap Latin letters for look-alikes, keeping hex addresses (0x...) valid."""

    def swap(match: re.Match[str]) -> str:
        word = match.group(0)
        if word.startswith("0x") or not any(char.isalpha() for char in word):
            return word
        return "".join(HOMOGLYPHS.get(char, char) for char in word)

    return _WORD.sub(swap, text)


def encode(text: str, encoding: str) -> str:
    """Render `text` in `encoding`: "plain", "base64", "morse" or "unicode_homoglyph"."""
    if encoding == "plain":
        return text
    if encoding == "base64":
        return base64.b64encode(text.encode()).decode()
    if encoding == "morse":
        return to_morse(text)
    if encoding == "unicode_homoglyph":
        return to_homoglyphs(text)
    raise ValueError(f"unknown encoding {encoding!r}")
