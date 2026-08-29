# comp-* fixtures — provenance

The three `comp-*-20260829` bundles are REAL producer output, frozen as
fixtures on 2026-08-29. They were never hand-written: a fixture that no
producer emitted is how a verifier ends up agreeing with a format nothing
actually produces.

## How they were made

Producer: `~/virp/camera/virp_camera.py` on 10.0.0.13, `main` at f770256
(the `feat/coverage-and-trust` merge — camera_segment/2 with signed
`capture_policy` and signed gap records).

1. A scratch O-node daemon (`virp-onode-prod`, VIRP tree at f770256) was
   started on 10.0.0.13 under `~/capture-completeness-evidence/` with its
   own O-Key, chain key, and D-1 chain-signing keypair
   (`virp-tool keygen chainsign`; key_id `9cc09cfd5afb42849cfde5db340abfd4`).
   The production daemon and live chain were not touched.
2. Synthetic segments were captured in REAL TIME with ffmpeg using the
   producer's own `--test-source` encoder settings (testsrc2 720p15,
   libx264 veryfast, 6 s segments, localtime overlay so no two segments are
   byte-identical). File mtimes are genuine capture-close times — the
   producer's replay time source. Three scenarios:
   - `comp-clean`: one continuous 48 s run;
   - `comp-gap`: 24 s, an ~20 s outage, 24 s — attested as two
     `replay` runs, so the producer emitted a signed `driver-restart` gap
     record on the first segment after the outage;
   - `comp-ux`: 24 s, a real ~1.6 s capture hole, 24 s — attested in ONE
     replay run under a declared policy of `--jitter-s 0.3
     --max-unexplained-gap-s 0`. The hole is below the producer's own 2 s
     disclosure tolerance (so no gap record is emitted) and above the
     signed policy's jitter: an unexplained interruption. With this
     producer version an honest producer self-discloses any hole > 2 s, so
     an unexplained gap can only exist in the (jitter, 2 s] band — larger
     unexplained holes exist only in pre-Fix-D historical records.
3. Each scenario was attested with `virp_camera.py replay --camera-id
   comp-<x> --sock <scratch onode.sock> --nominal-segment-s 6 ...` under
   its own producer keypair, then exported with
   `tools/export/export_bundle.py --db <scratch chain.db> --sessions
   camera:comp-<x>:2026-08-29 --artifacts --keys <chainsign pub>`.

## The producer's own audit of this chain (ground truth)

```
audited 24 camera evidence entries
COVERAGE: INTERRUPTED / UNEXPLAINED
  comp-clean               CONTINUOUS               no uncovered time; 1 boundary/ies beyond the declared jitter, all overlaps (seq 0..7, 8 record(s))
      OVERLAP      seq 6→7  windows overlap 2.3s (no time uncovered)
  comp-gap                 INTERRUPTED / ACCOUNTED  1 outage(s), 19.8 s not covered (seq 0..7, 8 record(s))
      ACCOUNTED    seq 3→4  hole 19.8s  gap=driver-restart
      OVERLAP      seq 2→3  windows overlap 2.3s (no time uncovered)
      OVERLAP      seq 6→7  windows overlap 2.3s (no time uncovered)
  comp-ux                  INTERRUPTED / UNEXPLAINED 1 outage(s), 1.5 s not covered (seq 0..7, 8 record(s))
      UNEXPLAINED  seq 3→4  hole 1.5s  gap=none
      OVERLAP      seq 2→3  windows overlap 2.3s (no time uncovered)
      OVERLAP      seq 6→7  windows overlap 2.3s (no time uncovered)
CONTENT REUSE: NONE
INTEGRITY: OK — all 24 stored bodies hash to their recorded artifact_hash; prev-hash chain intact; 24/24 producer signature(s) verified against 3 pinned key(s)
```

The overlaps are the producer's routine segment-finalize behaviour — the
same class of overlap as the 2026-08-24 replay records — and are exactly
what the completeness grader must report without ever counting as an
interruption.

Docket's `completeness_cli.rs` asserts Docket's grades agree with this
audit. The bundles also live in `~/docket-bundles/` for manual runs.
