# Canonical Host Resolution (Suite "Consumed by")

This note is for operators running the registry **coupled** with the Terraform
State Manager (TSM) sibling and wondering why a module's **"Consumed by"** panel
is empty when you expect it to list states. It explains the host-identity join
that powers that panel and the knobs that fix a host mismatch.

> You do not need any of this for a standalone registry. With
> `TFR_SUITE_SIBLING_URL` unset, nothing is polled and the panel never appears.
> See [ADR-012](adr/012-shared-identity-component.md) for the standalone-vs-coupled
> design.

---

## The mismatch this solves

When a Terraform state uses a registry module, TSM records the **host** from the
module's source address (e.g. `registry.example.com/team/vpc/aws`). The "Consumed
by" panel asks the sibling, in effect: *which states reference a module on **my**
host?* The registry answers by sending TSM the set of hosts it considers itself
reachable under. The join only works if those two host strings match exactly.

But the registry knows itself by two different values, and they often differ:

- **Discovery / base URL** (`server.base_url`) — the address the registry listens
  on and advertises for service discovery. Behind a reverse proxy this is often an
  internal address (e.g. `http://registry.internal:8080`).
- **Public / join-key URL** (`server.public_url`, via
  `ServerConfig.GetPublicURL()`) — the externally registered URL used for OAuth
  callbacks and the URL authors actually type into module sources.

If TSM captured the public host but the registry only offered its base host (or
vice versa), the exact-string join silently fails and the panel shows nothing.

---

## How resolution works

Two pieces, both from the shared `terraform-suite-identity` library so the registry
and TSM normalize identically.

### 1. CanonicalHost normalization

`suite.CanonicalHost` (in the shared module's `identity/suite/host.go`) folds away
the differences that should not matter for an identity match. For a raw host it:

- strips any accidental scheme prefix (keeps only the authority),
- lowercases the host and removes a trailing FQDN dot,
- folds an internationalized (Unicode/IDN) host to its **punycode** ASCII form,
  so a Unicode source address matches a punycode-stored one (best-effort: a host
  the IDNA lookup profile rejects, e.g. one with underscores, is left as the
  lowercased value rather than dropped), and
- drops a **default port** (`:80`/`:443`) while preserving any non-default port.

So `HTTPS://Registry.Example.com.:443/` and `registry.example.com` both canonicalize
to `registry.example.com`, and `café.example.com` matches `xn--caf-dma.example.com`.

### 2. The alias set (join key)

`canonicalHostSet` (in `internal/api/host.go`) builds the de-duplicated set of
canonical hosts the registry presents to TSM, in this order:

1. the **public** host (`GetPublicURL()`),
2. the **base / discovery** host (`base_url`), and
3. any operator-configured **aliases** (`TFR_SERVER_HOST_ALIASES`).

Empty/unparseable entries are dropped and duplicates are removed. Including both
the public and base hosts heals the common reverse-proxy case where authors still
address the base host even though `public_url` is set.

`moduleConsumersHandler` (`internal/api/suite.go`) emits every host in that set as
a repeated `&host=` query parameter on its server-to-server call to the sibling's
`/api/v1/consumers` endpoint; TSM matches a state if its captured host equals **any**
of them. The call carries the shared `X-Suite-Service-Token`
(`TFR_SUITE_SIBLING_TOKEN`), has a 2-second timeout, and returns an empty list on
any failure — so the panel hides and the page never blocks.

---

## When to set `TFR_SERVER_HOST_ALIASES`

Set it (comma-separated) when states reference the registry under a hostname that
is **neither** your `public_url` **nor** your `base_url`. Common cases:

- **Vanity CNAME** — modules are sourced from `tf.example.com` but the registry's
  `public_url` is `registry.example.com`.
- **Split-horizon / migrated DNS** — an old hostname still appears in committed
  state sources after a rename.
- **Port asymmetry** — `public_url` carries a non-default port (e.g.
  `registry.example.com:8443`) but authors reference the portless name.

```bash
# Registry public_url is https://registry.example.com, but states reference
# tf.example.com and an internal name. Widen the join key:
TFR_SERVER_HOST_ALIASES=tf.example.com,registry.internal
```

Aliases only **widen the join key** for the "Consumed by" lookup. They do not change
OAuth callbacks, CORS, TLS, or what the registry serves.

---

## Worked example

Configuration:

```yaml
server:
  base_url:   http://registry.internal:8080
  public_url: https://registry.example.com
  host_aliases: [tf.example.com]
```

The set the registry sends to TSM (canonicalized, de-duped, in order):

```text
registry.example.com        # from public_url (:443 dropped)
registry.internal:8080      # from base_url (non-default port kept)
tf.example.com              # from host_aliases
```

A state whose module source is `tf.example.com/team/vpc/aws` matches on the third
host and appears in the panel; one sourced from `REGISTRY.Example.com/...` matches
the first after canonicalization.

---

## Troubleshooting an empty panel

1. **Confirm coupling is live.** `GET /api/v1/ui/config` should report the sibling
   `state` as `active`. `degraded`/`unreachable` means discovery cannot reach TSM —
   fix `TFR_SUITE_SIBLING_URL` / network first.
2. **Confirm the service token is set on both sides.** `TFR_SUITE_SIBLING_TOKEN`
   here must equal TSM's `TSM_SUITE_SERVICE_TOKEN`. If it is unset, the proxy is
   inert and always returns empty.
3. **Compare hosts.** Look at the module source address recorded in TSM and at the
   registry's `public_url`/`base_url`. If the host is none of public, base, or an
   existing alias, add it to `TFR_SERVER_HOST_ALIASES`.
4. **Watch for case/port/IDN only.** Those are folded automatically; if a host
   differs only by case, a default port, a trailing dot, or Unicode vs punycode,
   it already matches and the problem is elsewhere.

---

## See also

- [ADR-012](adr/012-shared-identity-component.md) — Shared Identity Component
  (standalone vs coupled suite design).
- [docs/identity-schema.md](identity-schema.md) — the shared identity store.
- `docs/configuration.md` — full environment-variable reference.
