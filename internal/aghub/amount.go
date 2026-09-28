package aghub

import (
	"fmt"
	"math"

	"github.com/ANetResearch/ANetCore/payment"
)

// amountInt64 is how a wire amount becomes a ledger amount, and whether
// it can.
//
// On the wire an amount is a uint64 (payment.Authorization.Amount,
// payment.Receipt.Amount, a required amount); on this ledger it is an
// int64, because a balance moves both ways. A bare int64(n) for
// n > math.MaxInt64 is negative, and a negative amount run through "payer
// minus, payee plus" moves credit backwards: the balance check passes,
// since every balance is at least a negative number, then the payer's row
// rises and the payee's falls. Any agent that could sign could name a
// victim as payee and drain it, or redeem "2^64-1000" and be credited
// 1000. Refusing such amounts where they enter (parseAuth, the peer
// receipt and discharge paths, the operator's -clear), and again at every
// conversion, is what keeps a signature from reading as the opposite of
// what it says.
//
// Zero is refused too. It moves nothing, and would still use up a
// settlement record and write empty entries on both parties' ledgers.
//
// Every conversion of a wire amount in this package goes through here.
// A new int64(…Amount) anywhere else reopens the hole.
func amountInt64(n uint64) (int64, bool) {
	if n == 0 || n > math.MaxInt64 {
		return 0, false
	}
	return int64(n), true
}

// storedAmount is the reverse: a ledger amount read back from a row, as
// the uint64 a receipt or a response states. Only 1..MaxInt64 comes back.
// A row outside that range was written before amountInt64 existed (a
// settlement of 2^64-1000 was stored as -1000); converting it with a bare
// uint64(…) would re-sign, or echo, the overflowed amount as though it
// were a payment. deploy/audit-amount-overflow.sql lists such rows.
func storedAmount(n int64) (uint64, bool) {
	if n <= 0 {
		return 0, false
	}
	return uint64(n), true
}

// amountRefusal is the refusal for an amount amountInt64 rejects:
// invalid_amount, with the amount and the range in the detail.
func amountRefusal(what string, n uint64) *Refusal {
	return refuse(payment.ReasonInvalidAmount, "%s amount %d is outside 1..%d, the range this ledger can hold",
		what, n, int64(math.MaxInt64))
}

// errStoredAmount is the error for a stored row storedAmount rejects.
func errStoredAmount(table, id string, n int64) error {
	return fmt.Errorf("%s row %s holds amount %d, outside 1..%d; it was written by a hub without the "+
		"amount range check (see deploy/audit-amount-overflow.sql) and is not repeated",
		table, id, n, int64(math.MaxInt64))
}
