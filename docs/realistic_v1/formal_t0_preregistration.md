# ProxyTraffic Realistic v1 Formal T0 preregistration

## Status and objective

This document preregisters Formal T0 before any Formal T0 sample is collected. The target is a matched encrypted-traffic dataset for evaluating protocol classification without endpoint, identity, or capture-side shortcuts. The target consists of 100 seeds, three intensities, four modes, 300 atomic matched quartets, and 1,200 valid samples.

The collection implementation entering preregistration is Git commit `555e9e17c138e8f6dae42fe1f69fd10e1ea65b43`. Chromium is frozen at `151.0.7922.34` and Playwright at `1.62.0`. The required Git head for Formal T0 collection is the Git commit containing all artifacts in this preregistration; it is recorded as `FORMAL_T0_GIT_HEAD` after push and local/remote equality verification.

No Formal T0 sample may be collected until this preregistration passes its final audit. Network topology, routing/NAT, transparent proxy behavior, protocol configurations, browser navigation semantics, capture finalization, sample schema, and quality criteria are frozen.

## Topology and observation point

The Realistic User has application address `192.168.210.10` on `ens38`; `ens33` supplies neither an address nor a default route. Its Internet path is `192.168.210.10` to Collector `192.168.210.1`, then through the Collector. Original traffic is captured on Collector `ens38`. Model-input observed traffic is captured on Collector `ens39` (`192.168.220.10`) between Collector and proxy Server (`192.168.220.20`). Egress is captured on Server `ens33`. The three capture processes must be finalized before reorder, metadata, hashing, or upload.

The four modes are `direct`, `vless`, `shadowsocks`, and `trojan`. Direct exposes public TCP/443 connections at the observed point. Proxy modes must expose only their expected tunnel connection at the observed point and must have zero workload public-443 bypass. Original captures must contain no tunnel connection.

## Tranco source and hostname eligibility

The immutable ranking source is Tranco standard list ID `46W9X`, stored outside the repository at `/home/etip/datasets/plans/realistic_v1/t0_source/tranco_46W9X_top1m.csv`. It has 1,000,000 two-column rows with continuous ranks 1 through 1,000,000 and SHA256 `264830dfe5bbf84daeb23d482123d0a7eab1f6ee6830f08984c563be18d998aa`. Source integrity does not require every Tranco row to be a usable hostname.

All source rows were classified before reachability. Of 1,000,000 rows, 999,992 are syntax-eligible hostnames and eight are ineligible `_wildcard_` placeholders. Punycode is allowed when otherwise syntactically valid. Ineligible rows are never converted to URLs or sent to DNS, curl, or Playwright.

## Domain selection and reachability

Within each rank bucket, syntax-eligible candidates are ordered by strictly ascending Tranco rank. This is the deterministic selection and reserve order; no random or manual site selection is permitted. An unhealthy candidate is recorded and replaced only by the next candidate from the same bucket.

Reachability was audited from the actual Realistic User path using Chromium `151.0.7922.34`, Playwright `1.62.0`, concurrency eight, an isolated browser context per candidate, `wait_until="commit"`, a 30,000 ms main-navigation timeout, and a fixed 10,000 ms DOMContentLoaded observation window. A main document commit with a present response and HTTP status 200 through 399 is hard success. DOMContentLoaded timeout and third-party request failures are warnings. DNS failure, main-commit failure, missing response, unacceptable status, browser failure, or executor failure makes the candidate unreachable. Captcha-blocked pages and pages requiring a real login are policy-excluded.

The selected pool contains exactly 350 healthy domains from ranks 1–1,000, 100 from ranks 1,001–100,000, and 50 from ranks 100,001–1,000,000. Complete audit files retain surplus healthy candidates; selected files and the formal pool contain only the lowest-ranked required healthy candidates.

## Domain-disjoint split

The 500 domains are stratified by rank bucket using the deterministic sort key `SHA256("proxytraffic-realistic-v1-formal-t0-domain-split-v1" || NUL || source_sha256 || NUL || domain_id)`.

| Split | Rank 1–1,000 | Rank 1,001–100,000 | Rank 100,001–1,000,000 | Total |
|---|---:|---:|---:|---:|
| train | 210 | 60 | 30 | 300 |
| validation | 35 | 10 | 5 | 50 |
| test | 105 | 30 | 15 | 150 |

The three domain sets are pairwise disjoint. Seeds 001–060 may use only train domains, seeds 061–070 only validation domains, and seeds 071–100 only test domains.

## Workload and plan semantics

All 300 plans were generated before collection: 100 seeds times `light`, `medium`, and `heavy`. Every plan records seed, seed ID, split, intensity, pair group, deterministic RNG seed, domain IDs, URL and tab order, browser arguments, pre/post-navigation dwell, scroll count, scroll distance, scroll dwell, navigation timing, and navigation success semantics. There is no runtime RNG that changes workload content. Each quartet's four modes must consume the exact same plan bytes.

Light uses two URLs and one tab, medium four URLs and two tabs, and heavy six URLs and four tabs. The scroll-count, scroll-distance, and idle ranges retain the frozen Realistic v1 workload semantics. Plans are stored at `/home/etip/datasets/plans/realistic_v1/t0`, are mode `0444`, and are registered in `FORMAL_PLAN_SHA256SUMS.txt`.

Main navigation uses `wait_until="commit"` with a 30,000 ms hard timeout. A missing main response or status outside 200–399 is a hard failure. After commit, every event consumes the fixed 10,000 ms DOMContentLoaded observation window even if DOMContentLoaded arrives early. DOMContentLoaded timeout and third-party subresource failure are warnings and never alone fail an event. Sample success requires `hard_failure_count == 0`.

## Seed split and sample counts

Train uses seeds 001–060 (720 samples), validation 061–070 (120 samples), and test 071–100 (360 samples). Smoke/validation seeds 9001, 9099, 9199, 9299, 9301, and 9302 are excluded. Formal T0 totals 100 seeds, 300 quartets, and 1,200 valid samples.

## Mode rotation and quartet atomicity

Quartets are ordered by seed ascending and intensity `light`, `medium`, `heavy`. For quartet index modulo four, mode order is:

0. `direct`, `vless`, `shadowsocks`, `trojan`
1. `vless`, `shadowsocks`, `trojan`, `direct`
2. `shadowsocks`, `trojan`, `direct`, `vless`
3. `trojan`, `direct`, `vless`, `shadowsocks`

A seed and intensity form one atomic quartet. All modes must match on pair group, plan SHA256, Git head, browser version, and Playwright version.

## Retry and resume policy

A failed mode permits at most two explicit short-window retries using the same immutable plan. Every attempt records attempt ID, timestamp, reason, and result. Failed attempts move to `failed_artifacts/formal_t0/` and never count as valid data. Failure after two retries stops Formal collection and leaves the quartet incomplete; an isolated mode may not be completed days later without review.

Before every sample, the remote target is inspected. A non-empty `SAMPLE_COMPLETE` plus passing remote SHA causes `SKIP_VALID_COMPLETE`. Any existing incomplete or SHA-failing directory must not be overwritten; it moves to failed/quarantine scope before an explicit retry.

## Capture validation and paths

Local valid samples are rooted at `/home/etip/datasets/staging/realistic_v1/t0`; remote valid samples at `/home/dataset-assist-0/duwenbiao/Tunnel/proxydata/realistic_v1/t0`. Before each sample, Realistic residual capture count must be zero. After workload and tail traffic, all three tcpdump processes receive SIGINT and bounded wait; TERM and another bounded wait are fallback. Failure to exit fails the sample. PID absence and stable non-empty raw PCAP sizes are required before reorder, metadata, quality audit, hashing, upload, remote hashing, and finally `SAMPLE_COMPLETE`.

Every valid sample requires six non-empty PCAP files, workload/label/environment/pairing/quality metadata, zero hard workload failures, passing mode-specific tunnel and bypass checks, zero original tunnel exposure, passing local and remote SHA registries, non-empty completion marker, the preregistered Formal T0 Git head, and residual capture count zero.

## Model-visible feature policy

Training, validation, and testing may use only `observed.pcap`. Permitted observables are packet size, direction, timing, and flow boundaries or flow structure. Forbidden model-visible information includes `original.pcap`, `egress.pcap`, raw IP identity, raw port identity, DNS, SNI, certificate identity, endpoint identity, filename, sample path, sample ID, run ID, seed, protocol label, and implementation metadata.

## Formal audit gates

Before collection, audits must show: 500 formal domains; train/validation/test domain counts 300/50/150; zero domain overlap; correct rank-bucket allocation; 100 seeds split 60/10/30; 300 plans and pair groups; 1,200 scheduled samples; no missing SHA; no duplicate plan path; no invalid domain reference; no secret material in Git; and local Git head equal to actual `origin/main`.

During and after collection, audits require all expected valid samples and quartets, exact plan matching, correct mode counts, zero proxy public-443 bypass, zero original tunnel exposure, all quality reports passing, all capture finalization records passing, all local/remote SHA checks passing, and global Realistic residual process count zero.
