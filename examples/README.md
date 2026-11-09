# Examples

There's one file here you'll genuinely copy, plus one test fixture worth reading. Both links point at the canonical files in the repo, so what you see is what the code and tests use. Nothing on this page copies their contents.

- [config.example.yaml](../config.example.yaml) is the full activation example, comments and all. Copy it, swap in your own scope and repository, and point `token_env` at your token variable. [The configuration reference](../docs/reference/configuration.md) explains each key and links back here rather than repeating the file.
- [securityalert/envelope_golden_test.go](../securityalert/envelope_golden_test.go) holds the golden fixture: one synthetic Dependabot alert (number 42, for `@scope/left-pad`) and the exact fact it's expected to produce. It's not a data file, but it is the clearest input-in, fact-out example in the repo, and [concepts](../docs/concepts/README.md) walks through it.

If you're evaluating the collector, read the example config first and the golden test second. Between them you've seen both ends of the wire.
