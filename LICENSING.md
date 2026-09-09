# Standalone verifier boundary

Apache-2.0 applies to rights-controlled standalone verifier source:
crates/virp-verify/, its required crates/docket-bundle/ parsing/verification
library, tools/release/ verifier build tooling, and workspace Cargo.toml,
Cargo.lock, rust-toolchain.toml and deny.toml build/audit support. Package
license defaults in Cargo.toml do not license the manifest itself. Each carries LICENSE; the
crates retain NOTICE. LICENSE-APACHE preserves the original Apache text.

Everything else, including tools/export/ exporter/redaction tooling, has the
proprietary current/future policy in LICENSE. No commercial agreement is supplied.
The existing NOTICE is preserved as historical attribution; its blanket language
and references to the former layout do not expand this new policy's scope.
LICENSING-CONFLICTS.json records the transition. Earlier Apache permissions remain
valid for covered versions/material, including unchanged material carried forward.
This change does not revoke them or establish exclusive proprietary rights.
Existing notices name Third Level IT LLC; authority over that entity's or other
contributors' rights must not be inferred from this policy. Apache applies only
where the requester can license the code. Third-party permissions remain intact.

Build the standalone verifier with `cargo build --locked -p virp-verify`.
Only the two Apache crates and the dependencies in Cargo.lock are required;
no exporter, SDK, Docket service, UI, Contract tooling or Witness service source
is needed. The build script only obtains optional Git provenance. Test fixtures
are existing evidence, not a dependency on the software that generated them.
The existing CI also runs proprietary exporter integration tests. Those tests
are not prerequisites for building or running the standalone verifier. An
isolated source-only build is checked by the integration licensing milestone.

All packages explicitly declare licenses; workspace defaults are proprietary to
prevent accidentally opening future product crates. cargo-deny audits local
unpublished packages as well as registry dependencies. Dependencies retain their
own MIT/BSD/Unicode/Apache terms and notices; this is not a blanket relicense of
the dependency tree. The integration licensing check records the full Cargo graph
and rejects proprietary dependencies or unreviewed licenses/sources.
