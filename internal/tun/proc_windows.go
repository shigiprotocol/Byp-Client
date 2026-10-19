package tun

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")

	modkernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
	afInet              = 2  // AF_INET
	afInet6             = 23 // AF_INET6
)

type ProcessAppInfo struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

type cachedProcess struct {
	path      string
	name      string
	expiresAt int64
}

// ---------------------------------------------------------------------------
// Socket owner lookup
//
// FIX (random disconnects in split-tunnel mode):
// The old implementation merged every table refresh into a global port->pid map
// that was NEVER cleared, cached port->process for 10s, throttled refreshes to
// one per 15ms and negative-cached misses for 1.5s. Ephemeral ports are reused
// constantly, and apps like Steam open dozens of sockets in the same burst, so
// connections were regularly attributed to the wrong process (or to none) and
// were sent DIRECT instead of through the VPN (or vice versa) -> "drops".
//
// New approach:
//   - Each refresh builds a brand new snapshot (stale entries disappear).
//   - TCP is matched on local port + remote IP + remote port, so an old
//     snapshot can never give a wrong answer for a new connection.
//   - UDP (no remote address in the table) only trusts a snapshot taken AFTER
//     the lookup started.
//   - Concurrent lookups share a single refresh instead of being throttled
//     into failure, and misses are retried instead of negative-cached.
// ---------------------------------------------------------------------------

type tcpOwner struct {
	remote netip.AddrPort
	pid    uint32
}

type tcpSnapshot struct {
	takenAt int64
	byPort  map[uint16][]tcpOwner
}

type udpSnapshot struct {
	takenAt int64
	byPort  map[uint16]uint32
}

var (
	tcpSnap atomic.Pointer[tcpSnapshot]
	udpSnap atomic.Pointer[udpSnapshot]

	tcpRefreshMu sync.Mutex
	udpRefreshMu sync.Mutex

	procCache sync.Map // map[uint32]cachedProcess

	tableBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 131072) // 128KB initial capacity to avoid 2nd syscall
			return &b
		},
	}

	pathBufPool = sync.Pool{
		New: func() any {
			b := make([]uint16, windows.MAX_PATH*2)
			return &b
		},
	}
)

func getProcessImage(pid uint32) (string, string) {
	if pid == 0 || pid == 4 {
		return "System", "System"
	}

	nowNano := time.Now().UnixNano()
	if val, ok := procCache.Load(pid); ok {
		cp := val.(cachedProcess)
		if nowNano < cp.expiresAt {
			return cp.path, cp.name
		}
		procCache.Delete(pid)
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		// Negative cache protected/inaccessible processes briefly (was 30s) to avoid repeated OpenProcess syscalls
		procCache.Store(pid, cachedProcess{
			path:      "",
			name:      "",
			expiresAt: nowNano + int64(5*time.Second),
		})
		return "", ""
	}
	defer windows.CloseHandle(handle)

	bufPtr := pathBufPool.Get().(*[]uint16)
	defer pathBufPool.Put(bufPtr)
	buf := *bufPtr

	size := uint32(len(buf))
	r1, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 {
		procCache.Store(pid, cachedProcess{
			path:      "",
			name:      "",
			expiresAt: nowNano + int64(5*time.Second),
		})
		return "", ""
	}

	fullPath := syscall.UTF16ToString(buf[:size])
	baseName := filepath.Base(fullPath)

	procCache.Store(pid, cachedProcess{
		path:      fullPath,
		name:      baseName,
		expiresAt: nowNano + int64(15*time.Second),
	})

	return fullPath, baseName
}

// querySocketTable fetches the Windows TCP or UDP table, with bOrder = 0 (no kernel sorting overhead).
// The table can grow between the size probe and the real call, so it retries a few times.
func querySocketTable(proc *windows.LazyProc, family uintptr, tableClass uintptr) (*[]byte, uint32) {
	bufPtr := tableBufPool.Get().(*[]byte)

	for attempt := 0; attempt < 4; attempt++ {
		size := uint32(cap(*bufPtr))
		buf := (*bufPtr)[:size]

		r1, _, _ := proc.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, // bOrder = false
			family,
			tableClass,
			0,
		)

		if r1 == 0 && size >= 4 {
			return bufPtr, size
		}
		if r1 == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && size > 0 {
			*bufPtr = make([]byte, size+32768)
			continue
		}
		break
	}

	tableBufPool.Put(bufPtr)
	return nil, 0
}

func buildTCPSnapshot() *tcpSnapshot {
	snap := &tcpSnapshot{
		takenAt: time.Now().UnixNano(), // recorded BEFORE querying the kernel
		byPort:  make(map[uint16][]tcpOwner, 1024),
	}

	// 1. IPv4 TCP Table (sizeof(MIB_TCPROW_OWNER_PID) = 24)
	// state(0:4) localAddr(4:8) localPort(8:12) remoteAddr(12:16) remotePort(16:20) pid(20:24)
	if bufPtr, size := querySocketTable(procGetExtendedTcpTable, afInet, tcpTableOwnerPidAll); bufPtr != nil {
		buf := (*bufPtr)[:size]
		numEntries := binary.LittleEndian.Uint32(buf[0:4])
		offset := 4
		const rowSize = 24
		for i := uint32(0); i < numEntries && offset+rowSize <= len(buf); i++ {
			row := buf[offset : offset+rowSize]
			offset += rowSize
			localPort := binary.BigEndian.Uint16(row[8:10])
			pid := binary.LittleEndian.Uint32(row[20:24])
			if localPort == 0 || pid == 0 {
				continue
			}
			var ra [4]byte
			copy(ra[:], row[12:16])
			remote := netip.AddrPortFrom(netip.AddrFrom4(ra), binary.BigEndian.Uint16(row[16:18]))
			snap.byPort[localPort] = append(snap.byPort[localPort], tcpOwner{remote: remote, pid: pid})
		}
		tableBufPool.Put(bufPtr)
	}

	// 2. IPv6 / dual-stack TCP Table (sizeof(MIB_TCP6ROW_OWNER_PID) = 56)
	// localAddr(0:16) localScope(16:20) localPort(20:24) remoteAddr(24:40) remoteScope(40:44)
	// remotePort(44:48) state(48:52) pid(52:56)
	if bufPtr, size := querySocketTable(procGetExtendedTcpTable, afInet6, tcpTableOwnerPidAll); bufPtr != nil {
		buf := (*bufPtr)[:size]
		numEntries := binary.LittleEndian.Uint32(buf[0:4])
		offset := 4
		const rowSize = 56
		for i := uint32(0); i < numEntries && offset+rowSize <= len(buf); i++ {
			row := buf[offset : offset+rowSize]
			offset += rowSize
			localPort := binary.BigEndian.Uint16(row[20:22])
			pid := binary.LittleEndian.Uint32(row[52:56])
			if localPort == 0 || pid == 0 {
				continue
			}
			var ra [16]byte
			copy(ra[:], row[24:40])
			remote := netip.AddrPortFrom(netip.AddrFrom16(ra).Unmap(), binary.BigEndian.Uint16(row[44:46]))
			snap.byPort[localPort] = append(snap.byPort[localPort], tcpOwner{remote: remote, pid: pid})
		}
		tableBufPool.Put(bufPtr)
	}

	return snap
}

func buildUDPSnapshot() *udpSnapshot {
	snap := &udpSnapshot{
		takenAt: time.Now().UnixNano(),
		byPort:  make(map[uint16]uint32, 512),
	}

	// 1. IPv4 UDP Table (sizeof(MIB_UDPROW_OWNER_PID) = 12): localAddr(0:4) localPort(4:8) pid(8:12)
	if bufPtr, size := querySocketTable(procGetExtendedUdpTable, afInet, udpTableOwnerPid); bufPtr != nil {
		buf := (*bufPtr)[:size]
		numEntries := binary.LittleEndian.Uint32(buf[0:4])
		offset := 4
		const rowSize = 12
		for i := uint32(0); i < numEntries && offset+rowSize <= len(buf); i++ {
			row := buf[offset : offset+rowSize]
			offset += rowSize
			localPort := binary.BigEndian.Uint16(row[4:6])
			pid := binary.LittleEndian.Uint32(row[8:12])
			if localPort > 0 && pid > 0 {
				snap.byPort[localPort] = pid
			}
		}
		tableBufPool.Put(bufPtr)
	}

	// 2. IPv6 / dual-stack UDP Table (sizeof(MIB_UDP6ROW_OWNER_PID) = 28):
	// localAddr(0:16) scope(16:20) localPort(20:24) pid(24:28)
	if bufPtr, size := querySocketTable(procGetExtendedUdpTable, afInet6, udpTableOwnerPid); bufPtr != nil {
		buf := (*bufPtr)[:size]
		numEntries := binary.LittleEndian.Uint32(buf[0:4])
		offset := 4
		const rowSize = 28
		for i := uint32(0); i < numEntries && offset+rowSize <= len(buf); i++ {
			row := buf[offset : offset+rowSize]
			offset += rowSize
			localPort := binary.BigEndian.Uint16(row[20:22])
			pid := binary.LittleEndian.Uint32(row[24:28])
			if localPort > 0 && pid > 0 {
				if _, exists := snap.byPort[localPort]; !exists {
					snap.byPort[localPort] = pid
				}
			}
		}
		tableBufPool.Put(bufPtr)
	}

	return snap
}

// freshTCPSnapshot returns a snapshot taken at or after `notBefore`.
// Concurrent callers share one kernel query instead of being throttled.
func freshTCPSnapshot(notBefore int64) *tcpSnapshot {
	if s := tcpSnap.Load(); s != nil && s.takenAt >= notBefore {
		return s
	}
	tcpRefreshMu.Lock()
	defer tcpRefreshMu.Unlock()
	if s := tcpSnap.Load(); s != nil && s.takenAt >= notBefore {
		return s
	}
	s := buildTCPSnapshot()
	tcpSnap.Store(s)
	return s
}

func freshUDPSnapshot(notBefore int64) *udpSnapshot {
	if s := udpSnap.Load(); s != nil && s.takenAt >= notBefore {
		return s
	}
	udpRefreshMu.Lock()
	defer udpRefreshMu.Unlock()
	if s := udpSnap.Load(); s != nil && s.takenAt >= notBefore {
		return s
	}
	s := buildUDPSnapshot()
	udpSnap.Store(s)
	return s
}

// find returns the owning PID of the TCP socket (srcPort -> dst).
// With a valid dst the match is exact on the 4-tuple, so it is safe even on an older snapshot.
// Without dst it falls back to "the only non-listening owner of that port".
func (s *tcpSnapshot) find(srcPort uint16, dst netip.AddrPort) uint32 {
	if s == nil {
		return 0
	}
	owners := s.byPort[srcPort]
	if len(owners) == 0 {
		return 0
	}
	if dst.IsValid() {
		dAddr := dst.Addr().Unmap()
		for _, o := range owners {
			if o.remote.Port() == dst.Port() && o.remote.Addr() == dAddr {
				return o.pid
			}
		}
	}
	// Fallback: port-only match (ignore listening sockets which have no remote).
	var pid uint32
	for _, o := range owners {
		if o.remote.Port() == 0 {
			continue
		}
		if pid != 0 && pid != o.pid {
			return 0 // ambiguous
		}
		pid = o.pid
	}
	return pid
}

func lookupTCPOwner(srcPort uint16, dst netip.AddrPort) uint32 {
	start := time.Now().UnixNano()

	// Fast path: exact 4-tuple match in the current snapshot is always correct.
	if dst.IsValid() {
		if pid := tcpSnap.Load().find(srcPort, dst); pid != 0 {
			return pid
		}
	}

	for attempt := 0; attempt < 3; attempt++ {
		if pid := freshTCPSnapshot(start).find(srcPort, dst); pid != 0 {
			return pid
		}
		// Socket may not be visible yet; give the kernel a moment and look again.
		time.Sleep(time.Duration(attempt+1) * 4 * time.Millisecond)
		start = time.Now().UnixNano()
	}
	return 0
}

func lookupUDPOwner(srcPort uint16) uint32 {
	start := time.Now().UnixNano()
	for attempt := 0; attempt < 3; attempt++ {
		if pid := freshUDPSnapshot(start).byPort[srcPort]; pid != 0 {
			return pid
		}
		time.Sleep(time.Duration(attempt+1) * 4 * time.Millisecond)
		start = time.Now().UnixNano()
	}
	return 0
}

// ResolveProcessByPort finds the process that owns the local socket srcPort.
// dst (the remote endpoint of the flow) is used to match TCP sockets exactly; pass
// an invalid netip.AddrPort{} if unknown.
func ResolveProcessByPort(network string, srcPort uint16, dst netip.AddrPort) (exeName string, exePath string, pid uint32) {
	if srcPort == 0 {
		return "", "", 0
	}

	if strings.Contains(strings.ToLower(network), "udp") {
		pid = lookupUDPOwner(srcPort)
	} else {
		pid = lookupTCPOwner(srcPort, dst)
	}
	if pid == 0 {
		return "", "", 0
	}

	exePath, exeName = getProcessImage(pid)
	return exeName, exePath, pid
}

func GetRunningProcesses() ([]ProcessAppInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create process snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, fmt.Errorf("failed to get first process: %w", err)
	}

	seen := make(map[string]bool)
	var apps []ProcessAppInfo

	for {
		pid := entry.ProcessID
		name := syscall.UTF16ToString(entry.ExeFile[:])

		if pid > 4 && strings.HasSuffix(strings.ToLower(name), ".exe") {
			lowerName := strings.ToLower(name)
			if !isSystemProcess(lowerName) && !seen[lowerName] {
				fullPath, _ := getProcessImage(pid)
				if fullPath == "" {
					fullPath = name
				}
				seen[lowerName] = true
				apps = append(apps, ProcessAppInfo{
					PID:  pid,
					Name: name,
					Path: fullPath,
				})
			}
		}

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	sort.Slice(apps, func(i, j int) bool {
		return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name)
	})

	return apps, nil
}

func isSystemProcess(name string) bool {
	switch name {
	case "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
		"fontdrvhost.exe", "winlogon.exe", "dwm.exe", "sihost.exe",
		"taskhostw.exe", "runtimebroker.exe", "svchost.exe", "explorer.exe":
		return true
	default:
		return false
	}
}
