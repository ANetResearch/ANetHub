package wire3

import (
	"net/http"
	"sort"
)

// Reason is a hub reason code: the "reason" member of a wire-3 error body
// (core §2.15.1). The set is closed: a code that is not in the table
// below never goes on the wire, and TestWireRegistry checks the table
// against ANetCore wire/registry.json both ways.
type Reason string

// The hub reason codes, by class.
//
//anet:wire reasons.hub
const (
	// wire
	ReasonWireTooOld Reason = "wire_too_old"
	ReasonWireTooNew Reason = "wire_too_new"
	ReasonBadRequest Reason = "bad_request"
	ReasonNotFound   Reason = "not_found"
	ReasonTooLarge   Reason = "too_large"
	ReasonInternal   Reason = "internal"

	// authentication
	ReasonUnauthorized              Reason = "unauthorized"
	ReasonTSStale                   Reason = "ts_stale"
	ReasonReplayed                  Reason = "replayed"
	ReasonKeyRetired                Reason = "key_retired"
	ReasonIdentityHeadersNotAllowed Reason = "identity_headers_not_allowed"

	// relay
	ReasonBadEnvelope         Reason = "bad_envelope"
	ReasonExpired             Reason = "expired"
	ReasonBadExp              Reason = "bad_exp"
	ReasonSessionInvalid      Reason = "session_invalid"
	ReasonAccessInvalid       Reason = "access_invalid"
	ReasonRecipientUnknown    Reason = "recipient_unknown"
	ReasonTooLargeForStranger Reason = "too_large_for_stranger"
	ReasonKidStale            Reason = "kid_stale"
	ReasonRateLimited         Reason = "rate_limited"
	ReasonStrangersBusy       Reason = "strangers_busy"
	ReasonRedeliveryLimited   Reason = "redelivery_limited"
	ReasonMailboxFull         Reason = "mailbox_full"
	ReasonHomeUnreachable     Reason = "home_unreachable"
	ReasonRevocationListFull  Reason = "revocation_list_full"
	ReasonBucketTooNarrow     Reason = "bucket_too_narrow"

	// delivery confirmation
	ReasonBadStatusQuery Reason = "bad_status_query"
	ReasonBadAckItem     Reason = "bad_ack_item"

	// federation
	ReasonNotPeer            Reason = "not_peer"
	ReasonUnknownDestination Reason = "unknown_destination"
	ReasonSourceRate         Reason = "source_rate"

	// registration and key histories
	ReasonAdmissionRequired Reason = "admission_required"
	ReasonPowRequired       Reason = "pow_required"
	ReasonRegistrationQuota Reason = "registration_quota"
	ReasonInviteRemoved     Reason = "invite_removed"
	ReasonWitnessNotThisHub Reason = "witness_not_this_hub"
	ReasonAIDDeactivated    Reason = "aid_deactivated"
	ReasonUnknownAID        Reason = "unknown_aid"
	ReasonKELInvalid        Reason = "kel_invalid"
	ReasonKELFork           Reason = "kel_fork"
	ReasonKELRollback       Reason = "kel_rollback"
	ReasonKELTSOutOfWindow  Reason = "kel_ts_out_of_window"
	ReasonKeysRollback      Reason = "keys_rollback"

	// payment and reviews
	ReasonProofUnavailable        Reason = "proof_unavailable"
	ReasonGatewayRemoved          Reason = "gateway_removed"
	ReasonProbation               Reason = "probation"
	ReasonReviewExists            Reason = "review_exists"
	ReasonRequesterCommitMismatch Reason = "requester_commit_mismatch"
	ReasonReceiptNotReviewable    Reason = "receipt_not_reviewable"
	ReasonReviewWindowClosed      Reason = "review_window_closed"
)

// reasonInfo is what the hub writes for one code.
type reasonInfo struct {
	// status is the one HTTP status the code is sent with (core §2.15.1).
	status int
	// extra names the members the body carries besides reason and error.
	// Write fills the members of wire_too_old itself; for the others the
	// call site passes them in Refusal.Extra.
	extra []string
	// sentence is the default "error": what happened and what to do, in
	// one English sentence (the text after "; " is the next step). A call
	// site may pass a more specific one.
	sentence string
}

// reasons is the complete table of hub reason codes.
//
//anet:wire reasons.hub complete
var reasons = map[Reason]reasonInfo{
	// wire
	ReasonWireTooOld: {http.StatusUpgradeRequired, []string{"required_wire", "required_anet"},
		"This hub speaks hub wire 3 and needs anet 0.3.0 or later; update anet (anet update) and send again."},
	ReasonWireTooNew: {http.StatusBadRequest, nil,
		"This hub speaks hub wire 3, older than the caller's; ask the hub's operator to upgrade the hub, or use another hub."},
	ReasonBadRequest: {http.StatusBadRequest, nil,
		"This request is not in a form this hub accepts; fix the client (or update anet) and send again."},
	ReasonNotFound: {http.StatusNotFound, nil,
		"This hub has no such route or resource; check the method, the path and the identifiers in it."},
	ReasonTooLarge: {http.StatusRequestEntityTooLarge, nil,
		"The request body is larger than this route accepts; send a smaller one."},
	ReasonInternal: {http.StatusInternalServerError, nil,
		"This hub failed to handle the request; try again later, and tell the hub's operator if it keeps failing."},

	// authentication
	ReasonUnauthorized: {http.StatusUnauthorized, nil,
		"The request's signature does not verify against what this hub holds for the signer; sign it again with the current key."},
	ReasonTSStale: {http.StatusUnauthorized, []string{"floor"},
		"The signing time is not after this hub's record for this signer; sign again with a later time (see X-ANet-TS-Floor)."},
	ReasonReplayed: {http.StatusUnauthorized, nil,
		"This signed request was already used; sign a new one."},
	ReasonKeyRetired: {http.StatusUnauthorized, nil,
		"The request is signed with a key the signer has since rotated away from; sign it again with the current key."},
	ReasonIdentityHeadersNotAllowed: {http.StatusBadRequest, nil,
		"This route is anonymous; send the request without the X-ANet-AID, X-ANet-Seq and X-ANet-Sig headers."},

	// relay
	ReasonBadEnvelope: {http.StatusBadRequest, nil,
		"The body is not a sealed envelope this hub accepts, or it does not match X-ANet-Access; seal it again with anet 0.3.0 or later."},
	ReasonExpired: {http.StatusBadRequest, nil,
		"The envelope's expiry time has passed, so this hub does not carry it; seal a new one."},
	ReasonBadExp: {http.StatusBadRequest, nil,
		"The envelope's expiry time is further ahead than this hub accepts; seal it again with a nearer expiry."},
	ReasonSessionInvalid: {http.StatusUnauthorized, nil,
		"The sending session is missing, expired or does not verify; open a new session and send again."},
	ReasonAccessInvalid: {http.StatusForbidden, nil,
		"The delivery credential in X-ANet-Access was not accepted; use a current one from the recipient, or send without one."},
	ReasonRecipientUnknown: {http.StatusNotFound, nil,
		"No hub this hub can reach knows the recipient; check the recipient's AID."},
	ReasonTooLargeForStranger: {http.StatusRequestEntityTooLarge, nil,
		"The envelope is larger than the recipient accepts from senders who are not yet its contacts; send a smaller one."},
	ReasonKidStale: {http.StatusConflict, nil,
		"The envelope is sealed to an encryption key the recipient no longer publishes; fetch its current keys and seal it again."},
	ReasonRateLimited: {http.StatusTooManyRequests, nil,
		"Too many requests from this sender; send again after the seconds in Retry-After."},
	ReasonStrangersBusy: {http.StatusTooManyRequests, nil,
		"The recipient takes no more messages from senders who are not yet its contacts right now; send again after the seconds in Retry-After."},
	ReasonRedeliveryLimited: {http.StatusTooManyRequests, nil,
		"This envelope was queued too often in the last 24 hours; send it again after the seconds in Retry-After."},
	ReasonMailboxFull: {http.StatusInsufficientStorage, nil,
		"The recipient's mailbox on this hub is full; send again after the seconds in Retry-After."},
	ReasonHomeUnreachable: {http.StatusBadGateway, nil,
		"The recipient's hub did not answer; send again after the seconds in Retry-After."},
	ReasonRevocationListFull: {http.StatusTooManyRequests, nil,
		"This mailbox's revocation list is full; start a new mailbox key epoch, which empties it, instead of revoking more."},
	ReasonBucketTooNarrow: {http.StatusBadRequest, []string{"max_bits"},
		"The directory query asks for more prefix bits than this hub serves; query again with at most max_bits bits."},

	// delivery confirmation
	ReasonBadStatusQuery: {http.StatusBadRequest, nil,
		"A status check takes 1 to 64 items with a 16-byte rid and handle, all for one hub; fix the query and send again."},
	ReasonBadAckItem: {http.StatusBadRequest, nil,
		"An ack item is malformed (an id is required, handle and dack go together, at most 1000 items); fix it and send again."},

	// federation
	ReasonNotPeer: {http.StatusForbidden, nil,
		"This hub does not federate with yours; ask both operators to add each other as peers."},
	ReasonUnknownDestination: {http.StatusNotFound, nil,
		"No agent with this AID is registered on this hub; check the destination before forwarding again."},
	ReasonSourceRate: {http.StatusTooManyRequests, nil,
		"Too many requests from your hub; send again after the seconds in Retry-After."},

	// registration and key histories (HPP §5.5 for the first four)
	ReasonAdmissionRequired: {http.StatusForbidden, []string{"aid"},
		"This hub admits AIDs one by one; ask its operator to run: anet-hub admit <AID>."},
	ReasonPowRequired: {http.StatusForbidden, []string{"challenge"},
		"Registration here needs a proof of work; solve the challenge in this response and register again."},
	ReasonRegistrationQuota: {http.StatusTooManyRequests, nil,
		"Today's sign-ups from your network are used up; retry after Retry-After, or ask the operator to run anet-hub admit <AID>."},
	ReasonInviteRemoved: {http.StatusBadRequest, nil,
		"Hubs no longer use invites; register without one and send the admit command to the operator."},
	ReasonWitnessNotThisHub: {http.StatusBadRequest, nil,
		"Your key history names another hub as its witness; register at that hub, or rotate to make this hub your witness."},
	ReasonAIDDeactivated: {http.StatusGone, nil,
		"This identity is deactivated and cannot register again; create a new identity to come back."},
	ReasonUnknownAID: {http.StatusNotFound, nil,
		"This hub knows no agent with this AID; check the AID, or register it first."},
	ReasonKELInvalid: {http.StatusBadRequest, nil,
		"The key history does not verify; send the identity's full, unmodified key history."},
	ReasonKELFork: {http.StatusConflict, nil,
		"The key history conflicts with the one this hub holds for this AID; the identity has diverged, so retrying will not help."},
	ReasonKELRollback: {http.StatusConflict, nil,
		"The key history is older than the one this hub holds for this AID; send the full, current history."},
	ReasonKELTSOutOfWindow: {http.StatusBadRequest, nil,
		"A new key event's time is too far from this hub's clock; correct the system clock and sign the event again."},
	ReasonKeysRollback: {http.StatusConflict, []string{"stored_seq"},
		"The key set is not newer than the one this hub holds (stored_seq); publish one with a higher sequence number."},

	// payment and reviews (HPP §5.5)
	ReasonProofUnavailable: {http.StatusNotFound, nil,
		"No balance proof is kept for that period (proofs are kept for 14 days); fetch a newer period."},
	ReasonGatewayRemoved: {http.StatusGone, nil,
		"The hub gateway was removed in 0.3.0; install anet and call through its local A2A interface, where anet signs the payment for you: send payment-submitted without x402.payment.payload."},
	ReasonProbation: {http.StatusForbidden, nil,
		"New accounts cannot upload reviews during probation; retry after it ends."},
	ReasonReviewExists: {http.StatusConflict, nil,
		"This interaction has already been reviewed; each can be reviewed once, so retrying will not help."},
	ReasonRequesterCommitMismatch: {http.StatusBadRequest, nil,
		"Only the requester of this interaction can review it; retrying will not help."},
	ReasonReceiptNotReviewable: {http.StatusBadRequest, nil,
		"This receipt carries no review commitment; only tasks started with anet 0.3.0 can be reviewed."},
	ReasonReviewWindowClosed: {http.StatusBadRequest, nil,
		"Reviews are accepted up to 30 days after the interaction ends; this one can no longer be reviewed."},
}

// Reasons returns every hub reason code, sorted.
func Reasons() []Reason {
	out := make([]Reason, 0, len(reasons))
	for r := range reasons {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Known reports whether r is a hub reason code.
func Known(r Reason) bool {
	_, ok := reasons[r]
	return ok
}

// Status is the HTTP status r is sent with, or 0 for an unknown code.
func Status(r Reason) int { return reasons[r].status }

// Sentence is the default "error" sentence of r, or "" for an unknown code.
func Sentence(r Reason) string { return reasons[r].sentence }

// ExtraMembers names the members a body for r carries besides reason and
// error (nil for most codes).
func ExtraMembers(r Reason) []string { return append([]string(nil), reasons[r].extra...) }

// Waits reports whether a refusal with this status asks the caller to wait,
// and so carries Retry-After (core §2.12.1: 429, 502, 503, and the 507 of
// a full mailbox).
func Waits(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusInsufficientStorage:
		return true
	}
	return false
}
