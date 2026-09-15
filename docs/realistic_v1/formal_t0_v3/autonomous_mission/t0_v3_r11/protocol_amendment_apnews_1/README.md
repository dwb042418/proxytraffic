# Formal r11 amended continuation

The user authorized retaining samples 1–48 after deterministic apnews.com replacement qualification and a bounded 20-lifecycle delta validation. Stress v12 remains the base qualification. The original closure review is superseded by `../protocol_amendment.json`.

The schedule header and rows 1–48 are byte-identical to the original schedule. Original sample metadata, remote receipts, and completed attempt records remain unchanged. Three later workload plans replace only the apnews URL with tailscale.com. Browser, capture, retry, and acceptance implementation files remain unchanged.

Original sample49's HTTP403 attempt remains in `failed_artifacts`, with its original ledger preserved in `protocol_history/apnews_original`. It is excluded from final data. Replacement sample49 starts protocol attempt1 in a distinct immutable executor namespace. Each new protocol sample still has at most three attempts under the unchanged retry policy.

Use `manage_amended_formal_mission.py --config docs/realistic_v1/formal_t0_v3/autonomous_mission/t0_v3_r11/campaign_config.json --resume`, supervised by the recorded storage guard. The ordinary unamended runner does not resolve the two explicit input identities.

The final dataset is one explicitly amended protocol continuation: original frozen identity for samples 1–48, amended input identity for samples 49–1200. Both identities and the excluded original attempt remain auditable.
