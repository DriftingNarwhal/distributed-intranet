# Contributing

## Licensing of contributions

This project is **licensed under the Mozilla Public License 2.0 (`LICENSE`), with the specifications in `specs/` under Creative Commons Attribution 4.0 (`specs/LICENSE`)**. By contributing you agree your contribution is licensed
under those same terms.

Two notes specific to this repository. Changes to `specs/` are contributed under CC BY 4.0
rather than MPL. And **never add MPL's Exhibit B ("Incompatible With Secondary Licenses")
to a source file here** — MPL §3.3 is what allows an AGPL client such as
[ko-ls](https://github.com/DriftingNarwhal/ko-ls) to link these crates, and Exhibit B would
revoke that for the file it is added to.

## Sign your commits — the DCO

Every commit must carry a `Signed-off-by` line:

```
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` adds it for you. Set `user.name` and `user.email` first, because the
line has to be a real name you can be reached at.

**Why this exists, and why it is worth the friction.** A copyleft licence is only as good
as the project's right to ship the code under it. Without a record that each contributor
had the right to contribute and agreed to the terms, that right is assumed rather than
established — and if this ever needs relicensing, or a licence term needs enforcing, the
answer is every past contributor's permission individually. The sign-off is a per-commit
statement making that explicit, and it is far cheaper now than reconstructed later.

It is deliberately **not** a copyright-assignment CLA. You keep your copyright; nothing is
signed over to anybody. What the sign-off certifies is the [Developer Certificate of
Origin](https://developercertificate.org/), reproduced in full below.

## The gate

`cargo test --workspace` and `cargo clippy --workspace --all-targets` must both be clean
before a change lands. A run that skipped clippy because the toolchain lacked it has
checked half the gate and should say so.

---

Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
