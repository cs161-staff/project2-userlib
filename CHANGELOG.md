# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog][Keep a Changelog] and this project adheres to [Semantic Versioning][Semantic Versioning].

## [Unreleased]

## [v0.2.0] - 2021-03-29
### Changed
- Renamed `RSAKeySizeBytes` to `rsaKeySizeBits`, which fixes the mismatch
  between its name and its value, and also makes the variable private to the
  userlib module. This means it cannot be referenced in student implementations.

- Updated `Hash()` to return a []byte slice instead of a [64]byte array.

### Fixed
- Updated `HashKDF()` to return a more useful error message when the given key
  is the wrong size.

### Added
- Added `DatastoreGetBandwidth()` and `DatastoreResetBandwidth()` functions to
  help students write tests for the `AppendFile()` efficiency requirement.

---

## [Released]

## [v0.1.0] - 2021-02-21
CHANGELOG did not exist in this release.

---

<!-- Links -->
[Keep a Changelog]: https://keepachangelog.com/
[Semantic Versioning]: https://semver.org/

<!-- Versions -->
[Unreleased]: https://github.com/cs161-staff/project2-userlib/releases/v0.2.0...HEAD
[Released]: https://github.com/cs161-staff/project2-userlib/releases
[v0.2.0]: https://github.com/cs161-staff/project2-userlib/releases/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/cs161-staff/project2-userlib/releases/v0.1.0
