package version

// Version is the panel release version. CI/release builds override via -ldflags.
var Version = "0.2.11"

// BPFVersion tracks the bundled XDP object ABI/version.
var BPFVersion = "0.2.11"
