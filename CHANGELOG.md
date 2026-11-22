# Changelog

## [0.4.0](https://github.com/nostrfi/relay/compare/v0.3.1...v0.4.0) (2026-11-22)


### Bug Fixes

* **nip77:** cap negentropy sessions per connection ([#77](https://github.com/nostrfi/relay/issues/77)) ([bd85970](https://github.com/nostrfi/relay/commit/bd859703c3d75c3dab4fdd7b1aec65e9ee7b0f3c))


### Performance Improvements

* **nip77:** sync reads only id and created_at, capped by max_sync_events ([#75](https://github.com/nostrfi/relay/issues/75)) ([d1ed76c](https://github.com/nostrfi/relay/commit/d1ed76c4dc8ccd88368eeae43010d6219a6a945e))
* **storage:** bound DuckDB in two pools; add storage.memory_limit ([#80](https://github.com/nostrfi/relay/issues/80)) ([bf73231](https://github.com/nostrfi/relay/commit/bf73231aa476c8e0464b8bfffcabca3f08177be0))
* **ws:** allocation hygiene, and a full-entropy NIP-42 challenge ([#79](https://github.com/nostrfi/relay/issues/79)) ([4c30981](https://github.com/nostrfi/relay/commit/4c309813a178befcb3a6402c1792499f044d2320))
* **ws:** encode a broadcast event once, not once per subscription ([#78](https://github.com/nostrfi/relay/issues/78)) ([b68600a](https://github.com/nostrfi/relay/commit/b68600ada7193d7939865adb86add7d59799b97a))


### Miscellaneous Chores

* release 0.4.0 ([#81](https://github.com/nostrfi/relay/issues/81)) ([7ed4a83](https://github.com/nostrfi/relay/commit/7ed4a836860231da276a2cc0f0744a67830a0d45))

## [0.3.1](https://github.com/nostrfi/relay/compare/v0.3.0...v0.3.1) (2026-11-20)


### Bug Fixes

* **deploy:** pin the Caddy image to 2.11.9 by digest ([#68](https://github.com/nostrfi/relay/issues/68)) ([8e6abcb](https://github.com/nostrfi/relay/commit/8e6abcb2942d40b033fb439eac724abd5d74b396))

## [0.3.0](https://github.com/nostrfi/relay/compare/v0.2.0...v0.3.0) (2026-11-16)


### Features

* **admin:** store administrators and authorize them on operator endpoints ([#55](https://github.com/nostrfi/relay/issues/55)) ([#59](https://github.com/nostrfi/relay/issues/59)) ([936fbb6](https://github.com/nostrfi/relay/commit/936fbb6d9f086b174cc0a8f2ec2fec75a46f60a9))
* **dashboard:** manage administrators ([#57](https://github.com/nostrfi/relay/issues/57)) ([#66](https://github.com/nostrfi/relay/issues/66)) ([48e3f34](https://github.com/nostrfi/relay/commit/48e3f3409f5538ff73891a9e4eb961c9c410d1ae))
* **dashboard:** sign in administrators by relay role ([#56](https://github.com/nostrfi/relay/issues/56)) ([#62](https://github.com/nostrfi/relay/issues/62)) ([1e02e36](https://github.com/nostrfi/relay/commit/1e02e3677f6c0d28180a7eba2563a01df90e83fc))
* **nip01:** broadcast ephemeral events without storing them ([#53](https://github.com/nostrfi/relay/issues/53)) ([adb6654](https://github.com/nostrfi/relay/commit/adb66543b5dd6e58b555edca069b54692c0e84ba))


### Bug Fixes

* **admin:** address security review of administrator grants ([#61](https://github.com/nostrfi/relay/issues/61)) ([f07fa65](https://github.com/nostrfi/relay/commit/f07fa6558b38d725100aecd40834407e15a4d2a0))
* **dashboard:** address review of relay-role sign-in ([#56](https://github.com/nostrfi/relay/issues/56)) ([#63](https://github.com/nostrfi/relay/issues/63)) ([a88bdf9](https://github.com/nostrfi/relay/commit/a88bdf9c554504541eb31e2662457e7855160824))
* **dashboard:** revoke sessions on re-login and restart ([#56](https://github.com/nostrfi/relay/issues/56)) ([#64](https://github.com/nostrfi/relay/issues/64)) ([771f07e](https://github.com/nostrfi/relay/commit/771f07e15a5920ba94cdc5b67dfc5eab41f1f9e1))
* **nip98:** bind operator auth to this relay's origin and refuse replays ([#60](https://github.com/nostrfi/relay/issues/60)) ([#65](https://github.com/nostrfi/relay/issues/65)) ([8ef5fca](https://github.com/nostrfi/relay/commit/8ef5fca414edd0926a7b90c8391f6aa6a092aaff))

## [0.2.0](https://github.com/nostrfi/relay/compare/v0.1.0...v0.2.0) (2026-11-12)


### Features

* **dashboard:** filter events by several tags, including multi-letter tags ([#46](https://github.com/nostrfi/relay/issues/46)) ([2a0bda7](https://github.com/nostrfi/relay/commit/2a0bda731091556f9476356af19233aec2c72d59))
* **dashboard:** give the Metrics page the Overview's status card ([#50](https://github.com/nostrfi/relay/issues/50)) ([cc20a3d](https://github.com/nostrfi/relay/commit/cc20a3d25523c86366ec5adae4b7f9ac96c65449)), closes [#49](https://github.com/nostrfi/relay/issues/49)
* **dashboard:** show relay status, uptime and a refresh spinner on the Overview ([#43](https://github.com/nostrfi/relay/issues/43)) ([f9dc412](https://github.com/nostrfi/relay/commit/f9dc41273d898d40c741f7649c712761eb306597))


### Bug Fixes

* **nip42:** answer every AUTH message with OK ([#48](https://github.com/nostrfi/relay/issues/48)) ([e3240b2](https://github.com/nostrfi/relay/commit/e3240b25b850eaf0f11a87c0eaade7db1962e65e)), closes [#47](https://github.com/nostrfi/relay/issues/47)

## 0.1.0 (2026-11-11)


### Bug Fixes

* **deps:** build with Go 1.26.11 to clear standard-library advisories ([#41](https://github.com/nostrfi/relay/issues/41)) ([e227ab0](https://github.com/nostrfi/relay/commit/e227ab0b6dcbd2ede2228ebad56d82f20b19f81e))


### Continuous Integration

* cut releases from a release-please release PR ([38f87e9](https://github.com/nostrfi/relay/commit/38f87e9d9f21e0d43ca6b22044f820c91901959e))
