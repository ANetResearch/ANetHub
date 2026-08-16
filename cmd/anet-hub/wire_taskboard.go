//go:build !no_taskboard

package main

import (
	"github.com/ANetResearch/ANetHub/internal/taskboard"
)

func init() {
	registerMount(mount{name: "taskboard", wire: func(d *hubDeps) (func() error, error) {
		tb, err := taskboard.Open(d.data)
		if err != nil {
			return nil, err
		}
		d.root.Handle("/tasks/", taskboard.NewServer(tb, d.store).Handler())
		return tb.Close, nil
	}})
}
