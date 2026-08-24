package main

import (
	"sync"
	"time"
)

// Clients heartbeat /api/activity while a workout is on screen; the admin dashboard reads who's
// live. Purely ephemeral — never persisted. Expires shortly after the last ping.
type presenceEntry struct {
	Name      string `json:"name"`
	ExIdx     int    `json:"exIdx"`
	ExTotal   int    `json:"exTotal"`
	SetsDone  int    `json:"setsDone"`
	SetsTotal int    `json:"setsTotal"`
	StartedAt int64  `json:"startedAt"`
	UpdatedAt int64  `json:"-"`
}

const presenceTTL = 70 * time.Second // ~3.5x the 20s client heartbeat

var (
	presenceMu sync.Mutex
	presence   = map[string]*presenceEntry{}
)

func setPresence(uid string, e *presenceEntry) {
	e.UpdatedAt = time.Now().UnixMilli()
	presenceMu.Lock()
	presence[uid] = e
	presenceMu.Unlock()
}

func dropPresence(uid string) {
	presenceMu.Lock()
	delete(presence, uid)
	presenceMu.Unlock()
}

func livePresence(uid string) *presenceEntry {
	presenceMu.Lock()
	defer presenceMu.Unlock()
	p, ok := presence[uid]
	if !ok {
		return nil
	}
	if time.Now().UnixMilli()-p.UpdatedAt > presenceTTL.Milliseconds() {
		delete(presence, uid)
		return nil
	}
	return p
}

func startPresenceReaper() {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			now := time.Now().UnixMilli()
			presenceMu.Lock()
			for k, v := range presence {
				if now-v.UpdatedAt > presenceTTL.Milliseconds() {
					delete(presence, k)
				}
			}
			presenceMu.Unlock()
		}
	}()
}
