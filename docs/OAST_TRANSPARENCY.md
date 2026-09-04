# OAST Transparency

Phase 6 opsec requires that any third party in the data path is
**documented, bounded, and optional**. This page states exactly what the
out-of-band tunnel crosses, who can see it, and how to eliminate the third
party entirely.

## What OAST is for

SSRF, blind XXE, and callback-based findings cannot be confirmed from the
response the target gives you — the evidence arrives as a **callback**: the
vulnerable server makes an outbound request to a URL you planted. An
Out-of-Band Application Security Testing (OAST) tunnel gives that callback
somewhere to land, attributed to the lead that planted it.

Without it, an SSRF lead can only be *reported* ("probably fires"); with
it, the lead closes on a **received, attributed callback** — a fact.

## The default mode: YOUR OWN machine, no third party

BugWolf's default OAST is a **loopback listener inside the operator's
environment** (`tools/runtime/oast.py`). Callbacks from the target land on
the operator's own listener. Nothing crosses any third party. The tunnel
module exists for one reason only: when the target **cannot** reach the
operator (common cloud/CI environments where the hunt runs from an
ephemeral, non-routable sandbox), a public URL is needed.

## The public-tunnel path (opt-in, env-gated)

Enabled **only** when the operator sets `BUGWOLF_OAST_TUNNEL=1` (plus
`BUGWOLF_OAST_PUBLIC_URL`, or `BUGWOLF_OAST_TUNNEL_HOST` to pick the relay
— default relay: `serveo.net`):

1. BugWolf opens a local SSH port-forward to the relay host the operator
   chose. **No bugwolf code, payloads, or findings are uploaded** — the
   relay only sees raw TCP/HTTP callbacks that the TARGET itself sent to
   the advertised canary URL.
2. What crosses the relay, precisely:
   - the **canary hostname** the target resolves and connects to,
   - whatever the **vulnerable target application** puts in its outbound
     request (its own headers, the canary path, any injected content the
     bug causes it to send),
   - the callback metadata recorded for attribution (timestamp, source
     IP, method, path, headers).
3. Who can see it: the relay operator (and anyone observing the network
   between target and relay). Treat relay-observed callbacks as
   **observable by a third party** — never embed operator secrets,
   credentials, or client-confidential data in canary paths or payloads.
4. BugWolf **never** sends canary URLs through the relay's advertising
   channel in a way that leaks the operator's identity; the advertised
   hostname is the relay-assigned one (see
   `tools/runtime/oast_tunnel.py:DEFAULT_TUNNEL_HOST`).

## The self-hosted option (eliminates the third party)

For engagements where nothing may cross a third party:

```bash
# Point the tunnel at YOUR OWN relay (any SSH- forwarded host you own):
BUGWOLF_OAST_TUNNEL=1 \
BUGWOLF_OAST_TUNNEL_HOST=relay.yourdomain.example \
python3 -m tools.runtime.mission_runner --target <t> --paths <p> --json

# Or skip tunneling entirely — advertise a hostname YOU control:
BUGWOLF_OAST_PUBLIC_URL=https://oast.yourdomain.example \
python3 -m tools.runtime.mission_runner --target <t> --paths <p> --json
```

Running `relay.yourdomain.example` (a $5 VPS with SSH forwarding, or a
self-hosted interactsh server) means every byte of callback evidence
crosses only infrastructure **you own**. This is the recommended setup for
regulated engagements.

## Opsec summary

| Question | Loopback (default) | Public relay (opt-in) | Self-hosted |
|---|---|---|---|
| Third party in data path | none | relay operator | none |
| Who sees callbacks | operator only | operator + relay + network observers | operator only |
| Works when target can't reach operator | no | yes | yes (your relay) |
| Identity leak surface | none | relay-assigned hostname | your own DNS |

The safety boundary in one line: **OAST closes SSRF leads with attributed
callback facts; it never widens what may be probed** — the scope gate and
sandbox apply identically to tunnelled and loopback attribution.
