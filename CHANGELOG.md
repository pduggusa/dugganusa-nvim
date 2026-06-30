# Changelog

## 1.2.1 (2026-06-30)

### Added

- Documented the fourth live validation axis — Liveness ([/api/v1/feed-efficacy](https://analytics.dugganusa.com/api/v1/feed-efficacy)) — alongside novelty, timeliness, and accuracy.

### Changed

- Refreshed IOC corpus copy to 1.5M+ IOCs (~1.57M live) and ~38M documents across 65 indexes.
- Reworded the Timeliness validation bullet to point at the live kev-lead ledger instead of a fixed "~31 days ahead" average.

## 1.2.0 (2026-06-27)

### Documentation & Feed-Awareness

- **Feed-quality validation, now provable live.** README adds the three live, no-auth, durable validation endpoints behind the corpus this plugin queries: novelty ([feed-uniqueness](https://analytics.dugganusa.com/api/v1/feed-uniqueness), ~75%+ not in ThreatFox), timeliness ([kev-lead](https://analytics.dugganusa.com/api/v1/kev-lead), ~31 days ahead of CISA KEV), and accuracy ([spamhaus-validation](https://analytics.dugganusa.com/api/v1/spamhaus-validation), independently corroborated).
- **API-key enforcement corrected.** The STIX feed is API-key-enforced (anonymous → 401, unregistered Bearer → 429). Docs no longer say the free tier "works without a key" — it is a free *registered* key.
- **IOC count aligned to 1.10M+** in the README and the clean-result notification.

## 1.1.0

- Look up word/selection under cursor; specific-indicator lookup; AIPM audit command and keymaps.
