The curve of `../curve` without `require(cell.borrow_scheme == BORROW_DISABLED)` on the coin it holds. Its token
coin may then have borrowing on (KCC-20 section 5, borrowed receive): a stranger adds one token unit to it without
the curve in the transaction, and from then on `cell.amount == SUPPLY - sold` fails, so nobody can buy or sell.
BOR-01 catches it.
