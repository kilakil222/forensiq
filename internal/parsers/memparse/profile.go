package memparse

// WinProfile carries Windows kernel struct offsets for a band of build numbers.
// Offsets are byte distances from the start of each respective struct.
type WinProfile struct {
	BuildMin, BuildMax uint32
	Name               string

	// EPROCESS
	EProcDTB      int // Pcb.DirectoryTableBase
	EProcPID      int // UniqueProcessId
	EProcLinks    int // ActiveProcessLinks (LIST_ENTRY)
	EProcPPID     int // InheritedFromUniqueProcessId
	EProcCreate   int // CreateTime (FILETIME)
	EProcExitTime int // ExitTime; 0 == skip
	EProcPEB      int // Peb (user-mode pointer)
	EProcName     int // ImageFileName (15 bytes ASCII)
	EProcVadRoot  int // VadRoot (_RTL_AVL_TREE)

	// PEB
	PEBParams int // ProcessParameters

	// RTL_USER_PROCESS_PARAMETERS
	ParamsImagePath int // ImagePathName UNICODE_STRING
	ParamsCmdLine   int // CommandLine UNICODE_STRING

	// LIST_ENTRY layout (rarely changes)
	ListEntryFlink int
	ListEntryBlink int

	// _KLDR_DATA_TABLE_ENTRY
	KldrDllBase      int
	KldrEntryPoint   int
	KldrSizeOfImage  int
	KldrFullDllName  int
	KldrBaseDllName  int
	KldrInLoadOrder  int

	// _MMVAD_SHORT
	VadStartingVpn     int
	VadEndingVpn       int
	VadStartingVpnHigh int
	VadEndingVpnHigh   int
	VadFlags           int
	VadLeftChild       int
	VadRightChild      int
}

// Profiles is the registry of Windows builds we know how to parse.
// Order matters only for tie-breaking; selectProfile prefers the most specific match.
var Profiles = []WinProfile{
	{
		BuildMin: 19041, BuildMax: 22621,
		Name:          "Windows 10/11 x64 (19041-22621)",
		EProcDTB:      0x028,
		EProcPID:      0x2E8,
		EProcLinks:    0x2F0,
		EProcPPID:     0x3A8,
		EProcCreate:   0x310,
		EProcExitTime: 0x000,
		EProcPEB:      0x400,
		EProcName:     0x5A0,
		EProcVadRoot:  0x7D8,

		PEBParams: 0x020,

		ParamsImagePath: 0x060,
		ParamsCmdLine:   0x070,

		ListEntryFlink: 0,
		ListEntryBlink: 8,

		KldrInLoadOrder: 0x000,
		KldrDllBase:     0x030,
		KldrEntryPoint:  0x038,
		KldrSizeOfImage: 0x040,
		KldrFullDllName: 0x048,
		KldrBaseDllName: 0x058,

		VadStartingVpn:     0x018,
		VadEndingVpn:       0x01C,
		VadStartingVpnHigh: 0x020,
		VadEndingVpnHigh:   0x021,
		VadFlags:           0x024,
		VadLeftChild:       0x000,
		VadRightChild:      0x008,
	},
	{
		BuildMin: 17134, BuildMax: 18363,
		Name:          "Windows 10 x64 (1803-1909)",
		EProcDTB:      0x030, // confirmed from raw EPROCESS bytes: 0x028 is ProfileListHead.Blink
		EProcPID:      0x2E8,
		EProcLinks:    0x2F0,
		EProcPPID:     0x3E8, // confirmed: 0x3A8 was wrong
		EProcCreate:   0x310,
		EProcExitTime: 0x368, // confirmed: uniform +0x8 shift from standard 0x360; 0x318 is ProcessQuotaUsage[0]
		EProcPEB:      0x400, // confirmed: 0x3F8 was wrong
		EProcName:     0x458, // confirmed: 0x5A0 was wrong
		EProcVadRoot:  0x518, // confirmed: 0x7D8 was wrong (diag: null-page VAD at +0x518)

		PEBParams: 0x020,

		ParamsImagePath: 0x060,
		ParamsCmdLine:   0x070,

		ListEntryFlink: 0,
		ListEntryBlink: 8,

		KldrInLoadOrder: 0x000,
		KldrDllBase:     0x030,
		KldrEntryPoint:  0x038,
		KldrSizeOfImage: 0x040,
		KldrFullDllName: 0x048,
		KldrBaseDllName: 0x058,

		VadStartingVpn:     0x018,
		VadEndingVpn:       0x01C,
		VadStartingVpnHigh: 0x020,
		VadEndingVpnHigh:   0x021,
		VadFlags:           0x024,
		VadLeftChild:       0x000,
		VadRightChild:      0x008,
	},
	{
		BuildMin: 22000, BuildMax: 26100,
		Name:          "Windows 11 x64",
		EProcDTB:      0x028,
		EProcPID:      0x440,
		EProcLinks:    0x448,
		EProcPPID:     0x540,
		EProcCreate:   0x320,
		EProcExitTime: 0x000,
		EProcPEB:      0x550,
		EProcName:     0x5A8,
		EProcVadRoot:  0x7D8,

		PEBParams: 0x020,

		ParamsImagePath: 0x060,
		ParamsCmdLine:   0x070,

		ListEntryFlink: 0,
		ListEntryBlink: 8,

		KldrInLoadOrder: 0x000,
		KldrDllBase:     0x030,
		KldrEntryPoint:  0x038,
		KldrSizeOfImage: 0x040,
		KldrFullDllName: 0x048,
		KldrBaseDllName: 0x058,

		VadStartingVpn:     0x018,
		VadEndingVpn:       0x01C,
		VadStartingVpnHigh: 0x020,
		VadEndingVpnHigh:   0x021,
		VadFlags:           0x024,
		VadLeftChild:       0x000,
		VadRightChild:      0x008,
	},
}

// selectProfile picks the best-matching profile for build. If no band matches,
// returns the first profile as a best-effort default.
func selectProfile(build uint32) *WinProfile {
	for i := range Profiles {
		p := &Profiles[i]
		if build >= p.BuildMin && build <= p.BuildMax {
			return p
		}
	}
	if len(Profiles) > 0 {
		return &Profiles[0]
	}
	return nil
}
