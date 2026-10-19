package main

import (
	"time"

	"changeme/internal/tun"
)

// adapterSignature identifies the physical network the TUN session is bound to.
func adapterSignature(info tun.PhysicalAdapterInfo) string {
	ip := ""
	if info.LanIP != nil {
		ip = info.LanIP.String()
	}
	return info.Gateway + "|" + ip
}

// netWatchLoop watches the physical network while TUN mode is active.
//
// FIX: TUN mode binds Xray and every bypassed connection to the physical LAN IP and
// gateway detected at connect time. After Wi-Fi reconnects, sleep/resume, DHCP renew
// or switching networks, that IP/gateway changes and ALL traffic silently dies until
// the user disconnects and reconnects by hand. This loop detects the change and
// rebuilds the session automatically.
func (a *AppService) netWatchLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var (
		candidate      string // new signature seen, waiting to confirm (debounce)
		candidateHits  int
		pendingProfile string // reconnect still owed after a failed attempt
		pendingEpoch   uint64
		pendingTries   int
	)

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
		}

		a.mu.RLock()
		connected := a.connected
		mode := a.activeMode
		profileID := a.activeProfileID
		sig := a.tunNetSig
		epoch := a.userEpoch
		a.mu.RUnlock()

		// A previous automatic reconnect failed: keep retrying until it works,
		// the user connects/disconnects manually, or we give up.
		if pendingProfile != "" {
			if connected || epoch != pendingEpoch {
				pendingProfile = ""
				continue
			}
			if _, err := a.tunMgr.GetPhysicalAdapterInfo(); err != nil {
				continue // network still down, wait
			}
			pendingTries++
			a.log("Network is back, reconnecting TUN (attempt %d)...", pendingTries)
			if err := a.Connect(pendingProfile, "tun"); err == nil {
				pendingProfile = ""
			} else if pendingTries >= 12 {
				a.log("Automatic reconnect gave up: %v", err)
				pendingProfile = ""
			} else {
				a.mu.RLock()
				pendingEpoch = a.userEpoch
				a.mu.RUnlock()
			}
			continue
		}

		if !connected || mode != "tun" || sig == "" {
			candidate, candidateHits = "", 0
			continue
		}

		info, err := a.tunMgr.GetPhysicalAdapterInfo()
		if err != nil || info.LanIP == nil {
			// Network temporarily down (no physical default route). Nothing to do yet.
			candidate, candidateHits = "", 0
			continue
		}

		cur := adapterSignature(info)
		if cur == sig {
			candidate, candidateHits = "", 0
			continue
		}

		// Require the new network to be stable for two checks to avoid flapping.
		if cur != candidate {
			candidate, candidateHits = cur, 1
			continue
		}
		candidateHits++
		if candidateHits < 2 {
			continue
		}
		candidate, candidateHits = "", 0

		a.log("Physical network changed (%s -> %s), rebuilding TUN session...", sig, cur)
		_ = a.Disconnect()
		if err := a.Connect(profileID, "tun"); err != nil {
			a.log("Reconnect failed: %v (will retry)", err)
			pendingProfile = profileID
			pendingTries = 1
			a.mu.RLock()
			pendingEpoch = a.userEpoch
			a.mu.RUnlock()
		}
	}
}
