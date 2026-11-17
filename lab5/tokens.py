"""Token counting and prices, shared by every component.

The simulated backend bills with exactly these functions, so a gateway that uses
them can estimate a request's cost before it is sent. Prices are per million
tokens, in US dollars, and deliberately those of a frontier model, so that a
cost-DoS shows up as money.
"""
import math
import re

PRICE_IN_PER_M = 3.00
PRICE_OUT_PER_M = 15.00
MESSAGE_OVERHEAD = 4          # tokens per chat message, as most chat templates add

_PIECE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


def count_tokens(text):
    """Words and punctuation; a long word costs one token per six characters."""
    if not text:
        return 0
    return sum(max(1, math.ceil((m.end() - m.start()) / 6)) for m in _PIECE.finditer(text))


def count_messages(system, messages):
    n = count_tokens(system) + MESSAGE_OVERHEAD if system else 0
    for m in messages:
        n += count_tokens(str(m.get("content", ""))) + MESSAGE_OVERHEAD
    return n


def cost_usd(tokens_in, tokens_out):
    return round(tokens_in * PRICE_IN_PER_M / 1e6 + tokens_out * PRICE_OUT_PER_M / 1e6, 8)
