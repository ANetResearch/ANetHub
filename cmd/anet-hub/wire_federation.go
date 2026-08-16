//go:build !no_federation

package main

import (
	"log"

	"github.com/ANetResearch/ANetHub/internal/federation"
)

func init() {
	registerMount(mount{name: "federation", wire: func(d *hubDeps) (func() error, error) {
		cfg, err := federation.LoadConfig(d.data)
		if err != nil {
			return nil, err
		}
		fed, err := federation.New(d.data, cfg, d.hubID, storeDelivery{d.store})
		if err != nil {
			return nil, err
		}
		d.root.Handle("/fed/v1/", fed.Handler())
		if fed.Enabled() {
			d.srv0.SetForwarder(fed.TryForward)
			log.Printf("anet-hub federation: delivery=%s peers=%d", cfg.Delivery, len(cfg.Peers))
		}
		return fed.Close, nil
	}})
}
