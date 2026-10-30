`kcc20.sil` and `kcc20-minter.sil` are copied from the SilverScript repository's examples
(kaspanet/silverscript, `silverscript-lang/tests/examples/`, rev 15b7bc2), under its ISC license
(`LICENSE-silverscript`). TEST FIXTURE: `kcc20-minter.sil` has one check removed (`require(!recipientKcc20NewState.isMinter)`), so a recipient can be handed the minting power (FAM-08). Never deploy.
