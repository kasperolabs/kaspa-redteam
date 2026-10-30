`../curve/KCC20.sil` (the KCC-20 reference program) with two lines of its borrowed receive removed: the borrowed
coin must keep its owner, and must keep its KAS. BOR-03 (the borrower takes the coin) and BOR-05 (the borrower
takes its KAS) catch it; the unmodified program survives every BOR attack on all three borrow schemes.
