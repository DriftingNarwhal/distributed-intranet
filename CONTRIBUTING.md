# Contributing

## Licensing of contributions

This project is **licensed under the Mozilla Public License 2.0 (`LICENSE`), with the specifications in `specs/` under Creative Commons Attribution 4.0 (`specs/LICENSE`)**. By contributing you agree your contribution is licensed
under those same terms.

Two notes specific to this repository. Changes to `specs/` are contributed under CC BY 4.0
rather than MPL. And **never add MPL's Exhibit B ("Incompatible With Secondary Licenses")
to a source file here** — MPL §3.3 is what allows an AGPL client such as
[ko-ls](https://github.com/DriftingNarwhal/ko-ls) to link these crates, and Exhibit B would
revoke that for the file it is added to.

## The gate

`cargo test --workspace` and `cargo clippy --workspace --all-targets` must both be clean
before a change lands. A run that skipped clippy because the toolchain lacked it has
checked half the gate and should say so.
