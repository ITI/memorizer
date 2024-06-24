=============================================
Summary of memorizer-specific kernel versions
=============================================

- v6.6.30-memorizer-25
   - Allow values greater than 3 to be written to memorizer_enabled
   - Rename memorizer files
   - Fix BATS test not signaling failure correctly
   - Now that we know the tests can fail, don't fail
   - Fail job if any BATS test fails
   - Run the old memorizer test in the new system
   - Get rid of password for ssh key in test setup
   - Fix UACCESS enabled warnings
   - Create BATS test infrastructure.
   - Don't hang test if kernel panics
   - Don't hang test if key needs passphrase

- v6.6.30-memorizer-24
   - Update automated_test_doc.md
   - Update kernel to 6.6.30

- v6.6.3-memorizer-24
   - HAR-137 reduce number of WARN() calls.
   - HAR-138 widen index counter to 64 bits.
   - set up github actions

- v6.6.3-memorizer-23.1
   - work-around gitlab ci/cd bug
   - add kmap_stream open and close to dmesg log
   - bugfix: incorrectly identified overlapping allocations.
   - factor lt table walk into macro
