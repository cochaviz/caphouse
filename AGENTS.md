# Documentation Files for Agents

When applying changes to this codebase, consider updating the following user-facing documentation files as appropriate.

## Files

| File | Contents | Update when... |
|------|----------|----------------|
| `README.md` | Feature overview, installation, quick-start CLI examples, flags summary | New features added, flags changed, behaviour changes |
| `CHANGELOG.md` | Chronological list of unreleased and released changes | Any user-visible change (feature, fix, breaking change) |
| `docs/index.md` | Includes `README.md` verbatim via mkdocs `include` | Automatically reflects README changes; update if structure changes |
| `docs/quickstart.md` | Step-by-step CLI walkthrough (ingest, export, filter examples) | New commands or flags added, CLI UX changes, new workflows |
| `docs/reference.md` | Complete flag/option reference table for all sub-commands | Any flag added, removed, renamed, or with changed semantics |
| `docs/filters.md` | Filter syntax (`-q`) primitives, operators, examples | New filter primitives, changed syntax, new query features |
| `docs/storage.md` | Storage layout, compression, codec internals | Changes to table schema, codec, component system, or ClickHouse queries |
| `docs/development.md` | Running tests, dev environment setup, contributing guide | New test targets, build requirements, or dev workflow changes |
| `docs/changelog.md` | Includes `CHANGELOG.md` verbatim via mkdocs `include` | Automatically reflects CHANGELOG changes; update if structure changes |
| `cmd/caphouse/description.txt` | Long help text embedded as the root command `--help` description | Any change to supported modes, flags, or overall CLI behaviour |
| `cmd/caphouse/cli.go` | `Short` descriptions and `Use` strings for all cobra commands | Commands added/removed, flag names/semantics changed, sub-command restructuring |

## Notes

- `docs/index.md` and `docs/changelog.md` use `--8<--` includes and do not need manual edits when their source files are updated.
- Prefer updating `CHANGELOG.md` under the `## Unreleased` heading for every PR; the release process moves entries to a versioned heading.
- `docs/reference.md` is the canonical flag reference — keep it in sync with `cmd/caphouse/cli.go` flag registrations.
