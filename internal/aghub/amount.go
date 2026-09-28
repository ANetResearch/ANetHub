package aghub

import (
	"database/sql"
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

// execer is what addToRow writes through: the store's database or one of
// its transactions.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// addToRow adds delta to column col of the row of table whose key column
// keyCol is key, creating the row at delta, and refuses a result outside
// int64 with invalid_amount, moving nothing.
//
// amountInt64 bounds each amount; this bounds the sum. SQLite does not
// fail an integer overflow in "col + ?": it turns the result into a
// REAL, stored as such in the INTEGER column, so two in-range amounts
// whose sum passes MaxInt64 (two peer receipts of 2^63-1, say) left the
// account unreadable — every later read of it a scan error, /x402/supply
// an "integer overflow" — and every later sum on it rounded
// [redteam:si9]. The guard is in the statement, so the check and the write
// are one step inside the caller's transaction.
func addToRow(ex execer, table, keyCol, col, key string, delta int64) error {
	if delta == math.MinInt64 {
		return refuse(payment.ReasonInvalidAmount, "%s of %s: a change of %d cannot be applied", col, key, delta)
	}
	cmp, bound := "<=", int64(math.MaxInt64)-delta
	if delta < 0 {
		cmp, bound = ">=", math.MinInt64-delta
	}
	res, err := ex.Exec(fmt.Sprintf(
		`INSERT INTO %[1]s(%[2]s, %[3]s) VALUES(?,?)
		 ON CONFLICT(%[2]s) DO UPDATE SET %[3]s = %[3]s + ? WHERE %[3]s %[4]s ?`,
		table, keyCol, col, cmp), key, delta, delta, bound)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return refuse(payment.ReasonInvalidAmount,
			"%s %s of %s cannot take %+d: the result would leave the range this ledger can hold",
			table, col, key, delta)
	}
	return nil
}
