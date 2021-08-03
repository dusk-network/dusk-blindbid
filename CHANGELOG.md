# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add message getter for `Bid` [#150]
### Changed

- Update `dusk-poseidon` from `0.21` to `0.22` [#148]
- Update `dusk-pki` from `0.7` to `0.8` [#148]
- Update `phoenix-core` from `0.12` to `0.14.0-rc.0` [#148]

## [0.9.0] - 2021-07-05

### Added

- Add `phoenix-core` to deps. [#145]

### Changed

- Change Bid struct to include Message [#145]
- Change deps to remove the `rc` [#147]

## [0.8.0] - 2021-06-07

### Changed

- Change error module to include plonk & poseidon err variants [#131]
- Change crate features to not require `std` to use `proof` mod [#135]
- Change API getters returning by ref and not by value. [#124]
- Update `canonical` from `0.5` to `0.6` [#129]
- Update `dusk-plonk` from `0.6` to `0.8` [#129]
- Update `plonk_gadgets` from `0.5` to `0.6` [#129]
- Update `dusk-poseidon` from `0.18` to `0.21` [#129]
- Update `dusk-pki` from `0.6` to `0.7` [#129]
- Update `rand` from `0.7` to `0.8` [#129]
- Change CIRCUIT_ID def to come from code-hasher [#139]
- Change `rand` to be a dev-dependency [#143]

### Removed

- Remove `anyhow` from the crate [#131]
- Remove ZK-related components from the crate [#141]

## [0.7.1] - 2021-02-22

### Added

- Add `set_eligibility` for `Bid` [#125]

## [0.7.0] - 2021-02-17

### Added

- Add `extend_expiration()` for `Bid` [#121]

### Changed

- Change `Bid::set_pos()` to not return `&mut u64` [#121]

## [0.6.0] - 2021-02-12

### Changed

- Use crates.io deps for `dusk-pki` and `plonk_gadgets` now that they're published [#116]
- Improve naming for `Score` gen function [#118]
- Consensus round seed as BlsScalar instead of u64 [#113]

## [0.5.1] - 2021-02-02

### Changed

- Update dusk-pki to latest version

## [0.5.0] - 2021-01-27

### Added

- Added docs for the entire repo [#107]

### Changed

- Migrate repo to 2018 edition [#104]
- Update deps to latest versions [#103]
- Restructure the entire API of the crate

[#150](https://github.com/dusk-network/dusk-blindbid/issues/150)
[#148](https://github.com/dusk-network/dusk-blindbid/issues/148)
[#147](https://github.com/dusk-network/dusk-blindbid/pull/147)
[#145](https://github.com/dusk-network/dusk-blindbid/issues/145)
[#135](https://github.com/dusk-network/dusk-blindbid/issues/135)
[#124](https://github.com/dusk-network/dusk-blindbid/issues/124)
[#129](https://github.com/dusk-network/dusk-blindbid/issues/129)
[#139](https://github.com/dusk-network/dusk-blindbid/issues/139)
[#143](https://github.com/dusk-network/dusk-blindbid/issues/143)
[#131](https://github.com/dusk-network/dusk-blindbid/issues/131)
[#141](https://github.com/dusk-network/dusk-blindbid/issues/141)
[#125](https://github.com/dusk-network/dusk-blindbid/issues/125)
[#121](https://github.com/dusk-network/dusk-blindbid/issues/121)
[#116](https://github.com/dusk-network/dusk-blindbid/issues/116)
[#118](https://github.com/dusk-network/dusk-blindbid/issues/118)
[#113](https://github.com/dusk-network/dusk-blindbid/issues/113)
[#107](https://github.com/dusk-network/dusk-blindbid/issues/107)
[#104](https://github.com/dusk-network/dusk-blindbid/issues/104)
[#103](https://github.com/dusk-network/dusk-blindbid/issues/103)
