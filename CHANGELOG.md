# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 17-02-21

### Added

- Added `expiration_mut()` for `Bid`. [#121](https://github.com/dusk-network/dusk-blindbid/issues/121)

### Changed

- Changed `Bid::set_pos()` to not return `&mut u64`. [#121](https://github.com/dusk-network/dusk-blindbid/issues/121)

## [0.6.0] - 12-02-21

### Changed

- Use crates.io deps for `dusk-pki` and `plonk_gadgets` now that they're published.[#116](https://github.com/dusk-network/dusk-blindbid/issues/116)
- Improve naming for `Score` gen function [#118](https://github.com/dusk-network/dusk-blindbid/issues/118)
- Consensus round seed as BlsScalar instead of u64 [#113](https://github.com/dusk-network/dusk-blindbid/issues/113)

## [0.5.1] - 02-02-21

### Changed

- Update dusk-pki to latest version

## [0.5.0] - 27-01-21

### Added

- Added docs for the entire repo [#107](https://github.com/dusk-network/dusk-blindbid/issues/107)

### Changed

- Migrate repo to 2018 edition [#104](https://github.com/dusk-network/dusk-blindbid/issues/104)
- Update deps to latest versions [#103](https://github.com/dusk-network/dusk-blindbid/issues/103)
- Restructure the entire API of the crate
