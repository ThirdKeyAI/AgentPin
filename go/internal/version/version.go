// Package version exposes the AgentPin Go SDK version, kept in sync with the
// Rust crate, JavaScript package, and Python package on the same release.
package version

// Version is the current AgentPin Go SDK version. It must match the Rust
// crate, JavaScript package, and Python package versions; CI enforces this.
const Version = "0.3.0-alpha.1"

// ProtocolVersion is the AgentPin protocol version embedded in discovery
// documents and credentials.
const ProtocolVersion = "0.1"

// BundleVersion is the AgentPin trust bundle format version.
const BundleVersion = "0.1"
