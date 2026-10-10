//go:build (linux && !android) || freebsd

package dns

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withTempResolvConfPaths points the package-level resolv.conf paths at a temporary directory for
// the duration of the test, so fileConfigurator can be exercised without touching the real
// /etc/resolv.conf.
func withTempResolvConfPaths(t *testing.T) {
	t.Helper()

	origResolvPath := defaultResolvConfPath
	origBackupPath := fileDefaultResolvConfBackupLocation
	origUncleanPath := fileUncleanShutdownResolvConfLocation
	t.Cleanup(func() {
		defaultResolvConfPath = origResolvPath
		fileDefaultResolvConfBackupLocation = origBackupPath
		fileUncleanShutdownResolvConfLocation = origUncleanPath
	})

	tmpDir := t.TempDir()
	defaultResolvConfPath = filepath.Join(tmpDir, "resolv.conf")
	fileDefaultResolvConfBackupLocation = defaultResolvConfPath + ".original.netbird"
	fileUncleanShutdownResolvConfLocation = filepath.Join(tmpDir, "unclean_shutdown_resolv.conf")
}

func newTestFileConfigurator() *fileConfigurator {
	fc := &fileConfigurator{}
	fc.repair = newRepair(defaultResolvConfPath, fc.updateConfig)
	return fc
}

// Test_restoreAfterNetworkChange reproduces netbirdio/netbird#1399: after roaming from one
// network to another while still connected, disconnecting must restore the DNS of the network
// that is actually active, not a stale snapshot captured when NetBird first connected.
func Test_restoreAfterNetworkChange(t *testing.T) {
	withTempResolvConfPaths(t)

	homeResolvConf := "nameserver 192.168.1.1\nsearch home.local\n"
	require.NoError(t, os.WriteFile(defaultResolvConfPath, []byte(homeResolvConf), 0644))

	fc := newTestFileConfigurator()

	nbIP := netip.MustParseAddr("100.64.0.1")
	config := HostDNSConfig{
		ServerIP: nbIP,
		Domains:  []DomainConfig{{Domain: "netbird.cloud"}},
	}

	require.NoError(t, fc.applyDNSConfig(config, nil))
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.1")}, fc.getOriginalNameservers())

	// Roam to a different network while still connected: something external (e.g. a DHCP hook)
	// rewrites resolv.conf with the new network's own nameservers, the way file_repair_unix.go
	// observes it before repairing. Stop the watcher first so the test drives updateConfig
	// deterministically instead of racing the fsnotify goroutine for the same rewrite.
	fc.repair.stopWatchFileChanges()
	officeResolvConf := "nameserver 10.0.0.1\nsearch office.local\n"
	require.NoError(t, os.WriteFile(defaultResolvConfPath, []byte(officeResolvConf), 0644))

	officeCfg, err := parseDefaultResolvConf()
	require.NoError(t, err)
	require.NoError(t, fc.updateConfig([]string{"netbird.cloud"}, nbIP, officeCfg, nil))

	assert.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, fc.getOriginalNameservers(),
		"fallback nameservers must track the network that is actually active")

	require.NoError(t, fc.restoreHostDNS())

	restored, err := os.ReadFile(defaultResolvConfPath)
	require.NoError(t, err)
	assert.Contains(t, string(restored), "nameserver 10.0.0.1", "restore must bring back the active network's DNS")
	assert.NotContains(t, string(restored), "192.168.1.1", "restore must not bring back a stale, previously connected network's DNS")
}

func Test_restoreWithoutNetworkChange(t *testing.T) {
	withTempResolvConfPaths(t)

	homeResolvConf := "nameserver 192.168.1.1\nsearch home.local\n"
	require.NoError(t, os.WriteFile(defaultResolvConfPath, []byte(homeResolvConf), 0644))

	fc := newTestFileConfigurator()

	nbIP := netip.MustParseAddr("100.64.0.1")
	config := HostDNSConfig{
		ServerIP: nbIP,
		Domains:  []DomainConfig{{Domain: "netbird.cloud"}},
	}

	require.NoError(t, fc.applyDNSConfig(config, nil))
	// Re-applying with no external change to resolv.conf must not disturb the backup.
	require.NoError(t, fc.applyDNSConfig(config, nil))

	require.NoError(t, fc.restoreHostDNS())

	restored, err := os.ReadFile(defaultResolvConfPath)
	require.NoError(t, err)
	assert.Equal(t, homeResolvConf, string(restored))
}

func Test_isNetBirdManagedFile(t *testing.T) {
	withTempResolvConfPaths(t)

	managed, err := isNetBirdManagedFile(defaultResolvConfPath)
	require.NoError(t, err, "a missing file must not be treated as an error")
	assert.False(t, managed)

	require.NoError(t, os.WriteFile(defaultResolvConfPath, []byte("nameserver 192.168.1.1\n"), 0644))
	managed, err = isNetBirdManagedFile(defaultResolvConfPath)
	require.NoError(t, err)
	assert.False(t, managed)

	require.NoError(t, os.WriteFile(defaultResolvConfPath, []byte(fileGeneratedResolvConfContentHeaderNextLine+"nameserver 100.64.0.1\n"), 0644))
	managed, err = isNetBirdManagedFile(defaultResolvConfPath)
	require.NoError(t, err)
	assert.True(t, managed)
}

func Test_mergeSearchDomains(t *testing.T) {
	searchDomains := []string{"a", "b"}
	originDomains := []string{"c", "d"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 4 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 4)
	}
}

func Test_mergeSearchTooMuchDomains(t *testing.T) {
	searchDomains := []string{"a", "b", "c", "d", "e", "f", "g"}
	originDomains := []string{"h", "i"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 6 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 6)
	}
}

func Test_mergeSearchTooMuchDomainsInOrigin(t *testing.T) {
	searchDomains := []string{"a", "b"}
	originDomains := []string{"c", "d", "e", "f", "g"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 6 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 6)
	}
}

func Test_mergeSearchTooLongDomain(t *testing.T) {
	searchDomains := []string{getLongLine()}
	originDomains := []string{"b"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 1 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 1)
	}

	searchDomains = []string{"b"}
	originDomains = []string{getLongLine()}

	mergedDomains = mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 1 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 1)
	}
}

func Test_isContains(t *testing.T) {
	type args struct {
		subList []string
		list    []string
	}
	tests := []struct {
		args args
		want bool
	}{
		{
			args: args{
				subList: []string{"a", "b", "c"},
				list:    []string{"a", "b", "c"},
			},
			want: true,
		},
		{
			args: args{
				subList: []string{"a"},
				list:    []string{"a", "b", "c"},
			},
			want: true,
		},
		{
			args: args{
				subList: []string{"d"},
				list:    []string{"a", "b", "c"},
			},
			want: false,
		},
		{
			args: args{
				subList: []string{"a"},
				list:    []string{},
			},
			want: false,
		},
		{
			args: args{
				subList: []string{},
				list:    []string{"b"},
			},
			want: true,
		},
		{
			args: args{
				subList: []string{},
				list:    []string{},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run("list check test", func(t *testing.T) {
			if got := isContains(tt.args.subList, tt.args.list); got != tt.want {
				t.Errorf("isContains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func getLongLine() string {
	x := "search "
	for {
		for i := 0; i <= 9; i++ {
			if len(x) > fileMaxLineCharsLimit {
				return x
			}
			x = fmt.Sprintf("%s%d", x, i)
		}
	}
}
