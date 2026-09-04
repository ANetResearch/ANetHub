package main

// invite_ops.go — the operator's side of admission control.
//
// These run against a hub that is serving. The store is SQLite in WAL
// mode with a busy timeout, and the whole point of minting an invite is
// that somebody is waiting to onboard a machine right now; an op that
// required stopping the hub would mean dropping every live relay
// connection to add one node.

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

func runInviteOp(store *aghub.Store, required string, mint bool, label string,
	uses, days int, list bool, revoke string) error {

	if required != "" {
		on, err := strconv.ParseBool(required)
		if err != nil {
			return fmt.Errorf("-invite-required takes true or false, not %q", required)
		}
		if err := store.SetInviteRequired(on); err != nil {
			return err
		}
		if on {
			// Said explicitly, because the surprising half is the half an
			// operator did not ask about: turning admission on does not
			// remove anybody who is already registered.
			fmt.Println("admission: ON — new agents need an invite")
			fmt.Println("  agents already registered are unaffected and keep re-registering")
			fmt.Println("  mint one with: anet-hub -invite-new -label 'what it is for'")
		} else {
			fmt.Println("admission: OFF — anybody who can prove they hold their key may register")
		}
		return nil
	}

	if mint {
		if label == "" {
			// An unlabelled invite is unreadable three weeks later, which
			// is exactly when somebody asks which one leaked.
			return fmt.Errorf("-invite-new needs -label, so the listing means something later")
		}
		ttl := time.Duration(days) * 24 * time.Hour
		token, v, err := store.NewInvite(label, uses, ttl)
		if err != nil {
			return err
		}
		fmt.Printf("invite %s  (%s)\n", v.ID, label)
		fmt.Printf("  uses    %s\n", usesText(v.MaxUses))
		fmt.Printf("  expires %s\n", expiryText(v.ExpiresAt))
		fmt.Println()
		fmt.Printf("  %s\n", token)
		fmt.Println()
		// The hub keeps only a digest, so this really is the only time.
		fmt.Println("This is the only time the token is shown. The hub stores a hash of it,")
		fmt.Println("so it cannot be printed again — mint another if it is lost.")
		fmt.Println()
		fmt.Println("The machine joining runs:")
		fmt.Printf("  anet hub-register <hub-url> --name <name> --token %s\n", token)
		if !store.InviteRequired() {
			fmt.Println()
			fmt.Println("Note: admission is currently OFF, so this hub admits anybody and the")
			fmt.Println("invite is not yet needed. Turn it on with: anet-hub -invite-required true")
		}
		return nil
	}

	if revoke != "" {
		// Revoking twice is not an error to an operator: the gate is shut
		// either way, and the command is one somebody runs from a runbook
		// or a second terminal after being told an invite leaked. Reported
		// as a distinct outcome rather than silently as success, because
		// "I closed it" and "it was already closed" are different facts
		// about who could have used it in between.
		err := store.RevokeInvite(revoke)
		switch {
		case errors.Is(err, aghub.ErrInviteAlreadyRevoked):
			fmt.Printf("invite %s was already revoked — nothing to do\n", revoke)
			return nil
		case err != nil:
			return fmt.Errorf("revoke %s: %w", revoke, err)
		}
		fmt.Printf("invite %s revoked — it admits nobody new\n", revoke)
		fmt.Println("  agents already admitted on it stay; remove one with the admin plane")
		return nil
	}

	// list
	on := "OFF (anybody may register)"
	if store.InviteRequired() {
		on = "ON (new agents need an invite)"
	}
	fmt.Printf("admission: %s\n\n", on)
	invites, err := store.Invites()
	if err != nil {
		return err
	}
	if len(invites) == 0 {
		fmt.Println("no invites")
		return nil
	}
	for _, v := range invites {
		state := "live"
		switch {
		case v.RevokedAt != 0:
			state = "revoked"
		case v.ExpiresAt != 0 && time.Now().Unix() > v.ExpiresAt:
			state = "expired"
		case v.MaxUses > 0 && v.Uses >= v.MaxUses:
			state = "used up"
		}
		fmt.Printf("%-10s %-8s %s\n", v.ID, state, v.Label)
		fmt.Printf("           used %d/%s, expires %s\n",
			v.Uses, usesText(v.MaxUses), expiryText(v.ExpiresAt))
		for _, r := range v.Redeemers {
			fmt.Printf("           ← %s  %s\n", r.AID, time.Unix(r.At, 0).Format("2006-01-02 15:04"))
		}
	}
	return nil
}

func usesText(max int) string {
	if max == 0 {
		return "unlimited"
	}
	return strconv.Itoa(max)
}

func expiryText(at int64) string {
	if at == 0 {
		return "never"
	}
	return time.Unix(at, 0).Format("2006-01-02 15:04")
}
