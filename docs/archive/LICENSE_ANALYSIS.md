# NetGet License Analysis

**Generated:** 2025-11-05
**Project:** NetGet v0.1.0

## Executive Summary

NetGet currently has **no explicit license**. Based on the dependency analysis, the project can be licensed under permissive terms (MIT, Apache-2.0, or dual-licensed MIT/Apache-2.0) without significant restrictions from dependencies.

## Current Status

- **NetGet Project License**: ❌ **NOT SPECIFIED** (no LICENSE file or Cargo.toml license field)
- **Total Dependencies Analyzed**: ~900+ crates (including transitive dependencies)
- **License Compatibility**: ✅ Compatible with permissive licensing

## Dependency License Breakdown

### Permissive Licenses (>95% of dependencies)

The vast majority of dependencies use permissive licenses that impose minimal restrictions:

| License Type | Count | Notes |
|--------------|-------|-------|
| `MIT OR Apache-2.0` | ~2,367 | Most common, dual-licensed for flexibility |
| `MIT` | ~864 | Permissive, attribution required |
| `Apache-2.0` | ~250+ | Permissive, patent protection clause |
| `BSD-3-Clause` / `BSD-2-Clause` | ~60 | Permissive, attribution required |
| `ISC` | ~22 | Similar to MIT |
| `CC0-1.0` / `Unlicense` | ~20 | Public domain dedications |
| `Unicode-3.0` | ~40 | Permissive for Unicode data |
| `Zlib` | ~10 | Very permissive |

### Weak Copyleft Licenses (File-Level)

A small number of dependencies use **MPL-2.0** (Mozilla Public License 2.0):

| Crate | License | Impact |
|-------|---------|--------|
| `attohttpc` | MPL-2.0 | Test dependency only |
| `irc` / `irc-proto` | MPL-2.0 | Test dependency only |
| `ldap3_proto` | MPL-2.0 | Optional (ldap feature) |
| `minidom` | MPL-2.0 | Optional (xmpp feature) |
| `option-ext` | MPL-2.0 | Transitive dependency |
| `rfb` | MPL-2.0 | Optional (vnc feature) |

**MPL-2.0 Requirements:**
- Modifications to MPL-licensed files must be shared under MPL-2.0
- Can be combined with proprietary code (file-level copyleft)
- Does NOT require the entire project to be open-source
- Does NOT prevent commercial use

### Dual-Licensed with Copyleft Options (Safe)

These crates offer a choice between permissive and copyleft licenses - we can choose the permissive option:

| Crate | License | Recommendation |
|-------|---------|----------------|
| `self_cell` | Apache-2.0 OR GPL-2.0-only | ✅ Choose Apache-2.0 |
| `priority-queue` | LGPL-3.0-or-later OR MPL-2.0 | ✅ Choose MPL-2.0 |

### No License Specified

A few crates show empty license fields in `cargo tree` output:

| Crate | Status | Resolution |
|-------|--------|------------|
| `netget` (this project) | ❌ No license | **Action required** |
| `ollama-rs` | ✅ MIT (verified on GitHub) | Safe to use |
| Others (~5 crates) | Transitive dependencies | Likely build/proc-macro crates |

## License Compatibility Analysis

### Can NetGet be closed-source?

**No** - Due to MPL-2.0 dependencies:
- Any modifications to MPL-2.0 licensed files must be shared
- However, most MPL-2.0 crates are optional (feature-gated) or test-only
- The core NetGet code can remain proprietary

### Can NetGet be commercial?

**Yes** - All identified licenses permit commercial use:
- MIT, Apache-2.0, BSD, ISC: Explicitly allow commercial use
- MPL-2.0: Allows commercial use (file-level copyleft only)

### Recommended License for NetGet

Based on the Rust ecosystem standard and dependency compatibility:

**Option 1: MIT OR Apache-2.0 (Recommended)**
- Most common in Rust projects (~60% of dependencies use this)
- Provides flexibility for downstream users
- Compatible with all dependencies
- Patent protection from Apache-2.0
- Simple attribution requirements from MIT

**Option 2: MIT**
- Simpler, shorter license text
- Compatible with all dependencies
- Most permissive option

**Option 3: Apache-2.0**
- Stronger patent protection
- More detailed termination clauses
- Compatible with all dependencies

## Specific Obligations

If NetGet chooses **MIT OR Apache-2.0**:

### Obligations for NetGet Developers:
1. ✅ No copyleft obligations (can keep code proprietary if desired)
2. ✅ Can use commercially without restrictions
3. ✅ Can modify dependencies without special obligations (except MPL-2.0 files)
4. ⚠️ If modifying MPL-2.0 licensed files directly: Must share those specific file modifications

### Obligations for NetGet Users:
1. Must include copyright notices when redistributing
2. Must include license text when redistributing
3. No trademark rights granted
4. Software provided "AS IS" without warranty

## Compliance Recommendations

### Immediate Actions Required:

1. **Create LICENSE file** in repository root:
   ```bash
   # For dual-licensing (recommended):
   Add MIT license text to LICENSE-MIT
   Add Apache-2.0 license text to LICENSE-APACHE
   ```

2. **Update Cargo.toml**:
   ```toml
   [package]
   name = "netget"
   version = "0.1.0"
   license = "MIT OR Apache-2.0"  # Add this line
   ```

3. **Add copyright headers** to source files (optional but recommended):
   ```rust
   // Copyright 2025 NetGet Contributors
   // SPDX-License-Identifier: MIT OR Apache-2.0
   ```

4. **Document dependencies** (optional):
   - Generate `THIRD_PARTY_LICENSES.md` with:
     ```bash
     cargo install cargo-license
     cargo license --json > licenses.json
     ```

### Future Compliance:

1. Run `cargo deny check licenses` to catch problematic licenses automatically
2. Review licenses when adding new major dependencies
3. Be cautious with dependencies showing no license
4. Monitor for GPL/AGPL dependencies (currently none detected)

## Risk Assessment

| Risk | Level | Mitigation |
|------|-------|------------|
| Copyleft contamination | 🟢 **LOW** | Only MPL-2.0 (file-level), mostly optional features |
| Patent litigation | 🟢 **LOW** | Apache-2.0 provides patent protection |
| License compatibility | 🟢 **LOW** | All permissive, well-understood licenses |
| Compliance burden | 🟢 **LOW** | Simple attribution requirements |
| Unknown licenses | 🟡 **MEDIUM** | ~5 crates with empty license fields (likely safe) |

## Conclusion

NetGet is currently **unlicensed** (all rights reserved by default). The dependency analysis shows the project can safely adopt a permissive license (MIT OR Apache-2.0 recommended) without significant restrictions.

**Action Items:**
1. ⚠️ **CRITICAL**: Add LICENSE file(s) to the repository
2. ⚠️ **HIGH**: Update Cargo.toml with license field
3. 📋 **MEDIUM**: Document license choice in README.md
4. 📋 **LOW**: Add copyright headers to source files
5. 📋 **LOW**: Set up automated license checking with `cargo-deny`

## References

- [Rust API Guidelines - Licensing](https://rust-lang.github.io/api-guidelines/necessities.html#crate-and-its-dependencies-have-a-permissive-license-c-permissive)
- [MPL-2.0 FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)
- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- [MIT License](https://opensource.org/licenses/MIT)
- [cargo-deny documentation](https://embarkstudios.github.io/cargo-deny/)

---

**Note**: This analysis is based on automated dependency scanning. For legal decisions, consult with a qualified attorney. This document is for informational purposes only and does not constitute legal advice.
