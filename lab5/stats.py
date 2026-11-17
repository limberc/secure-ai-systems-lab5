"""Small statistics helpers for the scorer."""
import math


def wilson(k, n, z=1.96):
    """95% Wilson score interval for k successes in n trials, as (lo, hi)."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - r) / d), min(1.0, (c + r) / d))


def percentile(xs, q):
    if not xs:
        return float("nan")
    s = sorted(xs)
    i = (len(s) - 1) * q / 100.0
    lo, hi = math.floor(i), math.ceil(i)
    return s[lo] + (s[hi] - s[lo]) * (i - lo)
