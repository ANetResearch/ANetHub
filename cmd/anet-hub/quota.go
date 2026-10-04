package main

// anet-hub quota <AID> [--first-contacts-per-min N] [--non-contact-msgs N]
// [--non-contact-mib N] (sealed-sender SSR-H22):
//
//   - with no option, it shows the AID's values, one per line: the option
//     that sets it, the value, and "(default)" or the default it was raised
//     from;
//   - with options, it raises the values given (only those) and shows the
//     result the same way. A value below its default changes nothing and is
//     refused with quota_below_default, exit 1. A value equal to its default
//     puts the default back. A value that is not a whole number, or is above
//     2^31 − 1, is a usage error: quota_bad_value, exit 2.
//
// Like admit, it runs beside a running hub; the hub reads the change within
// a minute (aghub.Store.QuotaFor). Every other number of the sealed-sender
// area is a fixed value, not a flag (SSR-H21).

import (
	"errors"
	"flag"
	"math"
	"strconv"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// quotaValue is the value of one quota option: a whole number up to
// 2^31 − 1. Anything else is remembered as bad rather than only failing the
// parse, so the refusal can name the option (quota_bad_value).
type quotaValue struct {
	n   int64
	bad bool
}

func (v *quotaValue) String() string { return strconv.FormatInt(v.n, 10) }

// errQuotaValue fails the parse of a bad quota value; runQuota answers it
// with quota_bad_value.
var errQuotaValue = errors.New("quota_bad_value")

func (v *quotaValue) Set(s string) error {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > math.MaxInt32 {
		v.bad = true
		return errQuotaValue
	}
	v.n = n
	return nil
}

func runQuota(c *console, data string, args []string) int {
	const use = "anet-hub quota <AID> [--first-contacts-per-min N] [--non-contact-msgs N] [--non-contact-mib N]"
	fs, dataDir := newSubFlags("quota", data)
	var firstContacts, msgs, mib quotaValue
	opts := []struct {
		name string
		v    *quotaValue
	}{
		{aghub.QuotaFirstContactsPerMin, &firstContacts},
		{aghub.QuotaNonContactMsgs, &msgs},
		{aghub.QuotaNonContactMiB, &mib},
	}
	fs.Var(&firstContacts, aghub.QuotaFirstContactsPerMin, "first contacts this AID takes per minute")
	fs.Var(&msgs, aghub.QuotaNonContactMsgs, "messages from non-contacts its mailbox holds")
	fs.Var(&mib, aghub.QuotaNonContactMiB, "MiB from non-contacts its mailbox holds")
	pos, err := parseArgs(fs, args)
	if err != nil {
		// A value the option cannot take is named; anything else is the
		// usage line.
		for _, o := range opts {
			if o.v.bad {
				return c.say("quota_bad_value", map[string]string{"key": "--" + o.name})
			}
		}
		return c.usage(use)
	}
	if len(pos) != 1 {
		return c.usage(use)
	}
	var ch aghub.QuotaChange
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case aghub.QuotaFirstContactsPerMin:
			ch.FirstContactsPerMin = &firstContacts.n
		case aghub.QuotaNonContactMsgs:
			ch.NonContactMsgs = &msgs.n
		case aghub.QuotaNonContactMiB:
			ch.NonContactMiB = &mib.n
		}
	})
	aid := pos[0]
	if !aghub.ValidAID(aid) {
		return c.say("admit.bad_aid", map[string]string{"value": aid})
	}
	// The values first: a refused one opens nothing.
	var below *aghub.QuotaBelowDefaultError
	switch err := ch.Check(); {
	case errors.As(err, &below):
		return c.say("quota_below_default", map[string]string{"key": "--" + below.Field, "value": num(below.Default)})
	case err != nil:
		return c.usage(use)
	}
	store, code := openHub(c, *dataDir)
	if store == nil {
		return code
	}
	defer store.Close()
	var q aghub.Quota
	if ch == (aghub.QuotaChange{}) {
		q, err = store.QuotaOf(aid)
	} else {
		q, err = store.SetQuota(aid, ch)
	}
	if err != nil {
		return c.fail(err)
	}
	// The values are data, one per line and tab-separated like the
	// admission list: the option, the value, the default.
	def := aghub.DefaultQuota()
	for _, r := range []struct {
		name          string
		value, defVal int64
	}{
		{aghub.QuotaFirstContactsPerMin, q.FirstContactsPerMin, def.FirstContactsPerMin},
		{aghub.QuotaNonContactMsgs, q.NonContactMsgs, def.NonContactMsgs},
		{aghub.QuotaNonContactMiB, q.NonContactBytes >> 20, def.NonContactBytes >> 20},
	} {
		mark := "(default)"
		if r.value != r.defVal {
			mark = "(default " + num(r.defVal) + ")"
		}
		c.out.Write([]byte("--" + r.name + "\t" + num(r.value) + "\t" + mark + "\n"))
	}
	return 0
}
