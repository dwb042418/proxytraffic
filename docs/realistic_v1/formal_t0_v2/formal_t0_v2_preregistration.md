# ProxyTraffic Realistic v1 Formal T0 v2 Preregistration

## Amendment history and objective

Formal T0 v1 is permanently classified as `FORMAL_T0_V1_ABORTED_PRODUCTION_PILOT`. It produced 88 valid samples in 22 complete quartets at Git head `57f71d9fe8a267505d038dd1cb6bc3081bee010f`. During `seed008_medium`, `intuit.com` repeatedly returned HTTP 429 after a single health probe had returned HTTP 200. Three automatic attempts and one manually reviewed collection cycle failed. The v1 samples, failed attempts, retry ledger, domain artifacts, plans, schedule, and preregistration remain immutable historical evidence and are excluded from Formal T0 v2.

Formal T0 v2 addresses the demonstrated insufficiency of single-navigation reachability screening. It preregisters a fresh, independent 1,200-sample collection using a new 500-domain pool and 300 newly generated immutable plans. This amendment does not change the network, proxy, browser-navigation, capture-finalization, sample-schema, HTTP hard-failure, or quality semantics.

## Frozen execution semantics

The topology and observation point remain the validated Realistic User path through Collector and Server. Modes are `direct`, `vless`, `shadowsocks`, and `trojan`. Main navigation succeeds only when the main document commits within 30,000 ms and returns HTTP 200–399. HTTP 429 remains a hard failure. A DOMContentLoaded timeout and third-party subresource failures remain warnings. Chromium is `151.0.7922.34`, Playwright is `1.62.0`, QUIC is disabled, service workers are blocked, and every browser audit attempt uses a fresh context.

## Domain source and three eligibility gates

The immutable Tranco source is list `46W9X`, SHA256 `264830dfe5bbf84daeb23d482123d0a7eab1f6ee6830f08984c563be18d998aa`. The v1 500-domain pool was the v2 candidate base. Eligibility now requires all three gates:

1. valid hostname syntax under the frozen Tranco eligibility classification;
2. successful single-navigation reachability under the frozen browser policy;
3. quartet replay stability: four independent fresh-context main navigations separated by a fixed five-second interval, with 4/4 successful commits, 4/4 acceptable statuses, zero HTTP 429, and zero hard failures.

The base audit found 486 stable domains and 14 unstable domains. `intuit.com` returned 429 on all four attempts. Replacement candidates were taken deterministically in ascending rank order from the same Tranco rank bucket after the v1 audit reserve boundary. Every selected replacement passed syntax eligibility, a new single-navigation gate, and all four replay attempts. No domain was manually selected and no cross-bucket replacement occurred.

The final composition is 350 domains from ranks 1–1,000, 100 from ranks 1,001–100,000, and 50 from ranks 100,001–1,000,000. All 500 are replay-stable and none returned HTTP 429 during their recorded four-attempt replay audit.

## Domain-disjoint split

The v2 pool is stratified deterministically by rank bucket using `SHA256("proxytraffic-realistic-v1-formal-t0-domain-split-v2" || NUL || source_sha256 || NUL || domain_id)`. Train has 300 domains (210/60/30 by bucket), validation has 50 (35/10/5), and test has 150 (105/30/15). The three sets are disjoint. Seeds 001–060 may use only train domains, 061–070 only validation domains, and 071–100 only test domains.

## Workloads, plans, and schedule

Formal T0 v2 uses 100 seeds and `light`, `medium`, and `heavy` intensities, yielding 300 matched quartets and 1,200 planned samples. Light has two URL events and one tab, medium four events and two tabs, and heavy six events and four tabs. All domain choices, URL order, tabs, scroll counts, distances, and idle/dwell timing are fixed in the plans; runtime RNG cannot change workload content.

The 300 plans under `/home/etip/datasets/plans/realistic_v1/t0_v2` were newly generated for the v2 pool, are mode 0444, and are registered in `FORMAL_T0_V2_PLAN_SHA256SUMS.txt`. Four modes in a quartet must read identical plan bytes. Quartet-local mode rotation follows index modulo four: direct-first, VLESS-first, Shadowsocks-first, then Trojan-first.

## Atomicity, retries, resume, and capture validation

A seed plus intensity is an atomic quartet. A failed mode may receive at most two short-window retries with the same immutable plan; every failed attempt is recorded and stored outside the valid dataset. Exhaustion stops collection. Resume skips a remote sample only when its completion marker is non-empty, SHA verification passes, and Git/plan provenance matches. Incomplete or invalid directories are never overwritten.

Every valid sample requires non-empty original/observed/egress raw and reordered PCAPs, successful capture finalization, stable PCAP sizes, zero residual capture processes, zero workload hard failures, correct tunnel-port behavior, zero proxy public-443 bypass, correct original-side isolation, passing quality audit, passing local and remote SHA verification, complete schema, and a non-empty `SAMPLE_COMPLETE` marker.

## Cooling policy

The replay audit completed at `2026-08-29T06:22:15Z`. No Formal domain may be actively probed during the fixed 1,800-second cooling window, and Formal T0 v2 collection may not start before `2026-08-29T06:52:15Z`. This preregistration phase does not authorize collection.

## Model-visible feature policy

Training and evaluation may use only `observed.pcap`, limited to packet size, direction, timing, and flow boundaries/structure. Forbidden inputs include original or egress captures, raw IP or port identity, DNS, SNI, certificates, endpoint identity, filenames, paths, IDs, runs, seeds, protocol labels, and implementation metadata.

## Required preregistration and collection audits

Before collection: 500 Formal domains, 500 replay-stable domains, zero unstable/429 Formal domains, split counts 300/50/150, zero overlap, 100 seeds, 300 plans and pair groups, 1,200 schedule rows, complete SHA registry, valid domain references, secret audit PASS, and local Git head equal to actual `origin/main`.

After collection, an independent audit must require exactly 1,200 valid samples and 300 complete quartets, exact mode/intensity/split counts, correct preregistered plan hashes and Git head, zero pair mismatch, zero domain/seed split violation, zero proxy bypass, zero valid-sample capture-finalization failure, zero SHA failure, and global residual capture count zero.

Formal T0 v2 local sample root is `/home/etip/datasets/staging/realistic_v1/t0_v2`; remote root is `/home/dataset-assist-0/duwenbiao/Tunnel/proxydata/realistic_v1/t0_v2`. Neither root may reuse v1 samples.
