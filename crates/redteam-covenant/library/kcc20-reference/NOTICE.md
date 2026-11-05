# KCC-20 reference programs

These files are copied unchanged from argent-lang/kcc20-reference at commit
c8a087117735a1f87c5c6d115fcddeaf2562c784 (https://github.com/argent-lang/kcc20-reference),
licensed ISC by its authors.

- `KCC20.sil`, `PublicMint.sil`, `TokenSeed.sil`: `fixtures/public-mint/sil/`, the argentc output.
- `sil-abi.json`: the `sil_abi` part of `fixtures/public-mint/artifact.json` (compiled bytecode, state layout, entry tags).
- `templates.json`: the same programs as pins in the `kaspa-program-templates/1` format, with their KCC-1 template hashes.
  Regenerate from the artifact and compare; the tool refuses to start a scan if a stated hash does not match the bytes.

kaspa-redteam uses them to recognize these programs in real transactions (by template hash, exact match only) and to
rebuild their signature scripts when an attack changes a transaction. Nothing here is a claim that the programs are safe.

ISC License: Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is
hereby granted, provided that the above copyright notice and this permission notice appear in all copies. THE SOFTWARE
IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
