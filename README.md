# jout

::: note
**Jout** — JSON output
:::

**Jout** reimplements classic Unix utilities with JSON output by design.
Use `jout ls`, `jout ps`, etc., and receive stable, well-defined JSON
that’s safe for scripts, logs, and APIs.

- Familiar subcommands (`ls`, `ps`, …)
- Stable, documented schemas
- ISO 8601 times, byte-accurate sizes
- Works great with [**fx**](https://fx.wtf)

```bash
# Files as JSON
jout ls /var/log | fx '.map(x => ({name: x.name, size: x.size, mtime: x.mtime}))'

# Processes as JSON
jout ps --user "$USER" | fx .length
```

## Tools

- [x] `ls`
  - [x] Linux
  - [x] Mac
  - [x] Windows
- [x] `ps`
  - [x] Linux
  - [x] Mac
  - [x] Windows
- [ ] top
- [ ] pstree
- [ ] ping
- [ ] traceroute
- [ ] nslookup
- [ ] dig
- [ ] host
- [ ] whois
- [ ] ifconfig
- [ ] iwconfig
- [ ] route
- [ ] arp
- [ ] ss
- [ ] hostname
- [ ] mtr
- [ ] df
- [ ] du

## Versioning policy
- We do **not** ship breaking changes; public behavior and JSON schemas remain backward-compatible.
- From **v1.0** onward, JSON schemas are **stable**: no breaking changes within **1.x** (additive changes only).

## Timeline

### v0.x (pre-1.0)
**Focus:** Build out features and stabilize schemas.  
**Key work:**
- Expand command set.
- Iterate on and validate JSON schemas.
- Improve docs, and tooling.

### v1.0 (2026)
**Milestone:** JSON schema freeze and stability commitment.  
**Outcome:** Applications built against 1.0 schemas continue to work across all **1.x** releases.

### v1.x (2026+)
**Guarantees:**
- No breaking changes to JSON schemas.
- Backward-compatible, additive enhancements (new optional fields/commands, non-breaking defaults).

## License

[MIT](LICENSE)
