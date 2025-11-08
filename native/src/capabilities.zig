const std = @import("std");

// C bindings for libcap and prctl
const c = @cImport({
    @cInclude("sys/capability.h");
    @cInclude("sys/prctl.h");
});

// Capability constants
const CAP_NET_ADMIN: c_int = 12;
const CAP_EFFECTIVE: c_int = 0;
const CAP_PERMITTED: c_int = 1;
const CAP_INHERITABLE: c_int = 2;

// prctl constants
const PR_SET_NO_NEW_PRIVS: c_int = 38;
const PR_SET_DUMPABLE: c_int = 4;

/// Setup capabilities for netlink operations
/// This function verifies that CAP_NET_ADMIN is available
/// (should be inherited from file capabilities set via setcap)
pub fn setup() !void {
    // Check if we already have CAP_NET_ADMIN (from file capabilities)
    if (!hasNetAdmin()) {
        std.log.warn("CAP_NET_ADMIN capability is not active", .{});
        std.log.warn("Note: Netlink operations requiring CAP_NET_ADMIN will fail", .{});
        std.log.warn("Hint: Run 'sudo setcap cap_net_admin=ep priv/port_nftables' to grant capability", .{});
    }

    // Set PR_SET_NO_NEW_PRIVS to prevent gaining additional privileges
    if (c.prctl(PR_SET_NO_NEW_PRIVS, @as(c_ulong, 1), @as(c_ulong, 0), @as(c_ulong, 0), @as(c_ulong, 0)) != 0) {
        std.log.warn("Failed to set PR_SET_NO_NEW_PRIVS (non-fatal)", .{});
    }

    // Set PR_SET_DUMPABLE to 0 to prevent core dumps and ptrace
    if (c.prctl(PR_SET_DUMPABLE, @as(c_ulong, 0), @as(c_ulong, 0), @as(c_ulong, 0), @as(c_ulong, 0)) != 0) {
        std.log.warn("Failed to set PR_SET_DUMPABLE (non-fatal)", .{});
    }
}

/// Drop all capabilities on shutdown
pub fn teardown() void {
    // Get current capabilities
    const caps = c.cap_get_proc();
    if (caps == null) {
        std.log.warn("Failed to get process capabilities for teardown", .{});
        return;
    }
    defer _ = c.cap_free(caps);

    // Clear all capabilities
    if (c.cap_clear(caps) != 0) {
        std.log.warn("Failed to clear capabilities during teardown", .{});
        return;
    }

    // Apply cleared capabilities to process
    if (c.cap_set_proc(caps) != 0) {
        std.log.warn("Failed to apply cleared capabilities during teardown", .{});
        return;
    }
}

/// Check if the process has CAP_NET_ADMIN capability
/// Returns true if the capability is set, false otherwise
pub fn hasNetAdmin() bool {
    const caps = c.cap_get_proc();
    if (caps == null) {
        return false;
    }
    defer _ = c.cap_free(caps);

    var value: c.cap_flag_value_t = c.CAP_CLEAR;
    if (c.cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &value) != 0) {
        return false;
    }

    return value == c.CAP_SET;
}
