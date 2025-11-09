const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Allocator = mem.Allocator;

/// Sysctl parameter management for /proc/sys/net/*
///
/// This module provides safe read/write operations for network-related
/// sysctl parameters. All operations require CAP_NET_ADMIN capability.
///
/// Security:
/// - Strict parameter whitelist (no path traversal)
/// - Value validation per parameter type
/// - Limited to /proc/sys/net/* only

/// Whitelisted sysctl parameters
/// Only these parameters can be read or written via the port.
/// This prevents path traversal and unauthorized filesystem access.
const ALLOWED_PARAMS = [_][]const u8{
    // IPv4 Core
    "net.ipv4.ip_forward",
    "net.ipv4.conf.all.forwarding",
    "net.ipv4.conf.default.forwarding",

    // IPv4 TCP
    "net.ipv4.tcp_syncookies",
    "net.ipv4.tcp_timestamps",
    "net.ipv4.tcp_tw_reuse",
    "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_keepalive_time",
    "net.ipv4.tcp_keepalive_probes",
    "net.ipv4.tcp_keepalive_intvl",
    "net.ipv4.ip_local_port_range",

    // IPv6 Core
    "net.ipv6.conf.all.forwarding",
    "net.ipv6.conf.default.forwarding",

    // Netfilter / Connection Tracking
    "net.netfilter.nf_conntrack_max",
    "net.netfilter.nf_conntrack_tcp_timeout_established",
    "net.netfilter.nf_conntrack_tcp_timeout_time_wait",
    "net.netfilter.nf_conntrack_tcp_timeout_close_wait",
    "net.netfilter.nf_conntrack_tcp_timeout_fin_wait",
    "net.nf_conntrack_max",

    // ICMP
    "net.ipv4.icmp_echo_ignore_all",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.icmp_ratelimit",

    // IPv4 Security
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.send_redirects",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",

    // IPv6 Security
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.default.accept_redirects",
    "net.ipv6.conf.all.accept_source_route",
    "net.ipv6.conf.default.accept_source_route",
    "net.ipv6.conf.all.accept_ra",
    "net.ipv6.conf.default.accept_ra",
    "net.ipv6.conf.all.accept_ra_defrtr",
    "net.ipv6.conf.all.accept_ra_pinfo",
};

/// Check if a parameter is in the whitelist
fn isAllowedParam(param: []const u8) bool {
    for (ALLOWED_PARAMS) |allowed| {
        if (mem.eql(u8, param, allowed)) {
            return true;
        }
    }
    return false;
}

/// Convert sysctl dotted notation to filesystem path
/// Example: "net.ipv4.ip_forward" -> "/proc/sys/net/ipv4/ip_forward"
fn paramToPath(param: []const u8, buf: []u8) ![]const u8 {
    if (buf.len < 256) return error.BufferTooSmall;

    // Start with /proc/sys/
    var pos: usize = 0;
    const prefix = "/proc/sys/";
    @memcpy(buf[pos..][0..prefix.len], prefix);
    pos += prefix.len;

    // Convert dots to slashes
    for (param) |c| {
        if (pos >= buf.len - 1) return error.BufferTooSmall;
        buf[pos] = if (c == '.') '/' else c;
        pos += 1;
    }

    return buf[0..pos];
}

/// Read a sysctl parameter value
pub fn getSysctl(allocator: Allocator, param: []const u8) ![]const u8 {
    // Validate parameter is whitelisted
    if (!isAllowedParam(param)) {
        return error.ParameterNotWhitelisted;
    }

    // Convert to filesystem path
    var path_buf: [256]u8 = undefined;
    const path = try paramToPath(param, &path_buf);

    // Open and read file
    const file = fs.openFileAbsolute(path, .{}) catch |err| {
        std.log.err("Failed to open sysctl parameter '{s}': {}", .{param, err});
        return error.ParameterNotFound;
    };
    defer file.close();

    // Read value (most sysctl values are small)
    var value_buf: [4096]u8 = undefined;
    const bytes_read = try file.readAll(&value_buf);

    // Trim trailing newline/whitespace
    var end = bytes_read;
    while (end > 0 and (value_buf[end-1] == '\n' or value_buf[end-1] == ' ' or value_buf[end-1] == '\t')) {
        end -= 1;
    }

    // Allocate and return trimmed value
    const value = try allocator.alloc(u8, end);
    @memcpy(value, value_buf[0..end]);
    return value;
}

/// Validate sysctl value based on parameter type
fn validateValue(param: []const u8, value: []const u8) !void {
    // Boolean parameters (0 or 1)
    const bool_params = [_][]const u8{
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.forwarding",
        "net.ipv4.conf.default.forwarding",
        "net.ipv4.tcp_syncookies",
        "net.ipv4.tcp_timestamps",
        "net.ipv4.tcp_tw_reuse",
        "net.ipv6.conf.all.forwarding",
        "net.ipv6.conf.default.forwarding",
        "net.ipv4.icmp_echo_ignore_all",
        "net.ipv4.icmp_echo_ignore_broadcasts",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.default.rp_filter",
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.default.accept_source_route",
        "net.ipv4.conf.all.send_redirects",
        "net.ipv4.conf.default.send_redirects",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.default.accept_redirects",
        "net.ipv6.conf.all.accept_redirects",
        "net.ipv6.conf.default.accept_redirects",
        "net.ipv6.conf.all.accept_source_route",
        "net.ipv6.conf.default.accept_source_route",
        "net.ipv6.conf.all.accept_ra",
        "net.ipv6.conf.default.accept_ra",
        "net.ipv6.conf.all.accept_ra_defrtr",
        "net.ipv6.conf.all.accept_ra_pinfo",
    };

    for (bool_params) |bool_param| {
        if (mem.eql(u8, param, bool_param)) {
            if (!mem.eql(u8, value, "0") and !mem.eql(u8, value, "1")) {
                return error.InvalidValue;
            }
            return;
        }
    }

    // Port range parameter (special format: "min max")
    if (mem.eql(u8, param, "net.ipv4.ip_local_port_range")) {
        // Format: "32768 60999"
        var iter = mem.splitScalar(u8, value, ' ');
        const min_str = iter.next() orelse return error.InvalidValue;
        const max_str = iter.next() orelse return error.InvalidValue;
        if (iter.next() != null) return error.InvalidValue; // Extra values

        const min = std.fmt.parseInt(u32, min_str, 10) catch return error.InvalidValue;
        const max = std.fmt.parseInt(u32, max_str, 10) catch return error.InvalidValue;

        if (min >= max or min < 1024 or max > 65535) {
            return error.InvalidValue;
        }
        return;
    }

    // Numeric parameters (positive integers)
    const num_params = [_][]const u8{
        "net.netfilter.nf_conntrack_max",
        "net.netfilter.nf_conntrack_tcp_timeout_established",
        "net.netfilter.nf_conntrack_tcp_timeout_time_wait",
        "net.netfilter.nf_conntrack_tcp_timeout_close_wait",
        "net.netfilter.nf_conntrack_tcp_timeout_fin_wait",
        "net.nf_conntrack_max",
        "net.ipv4.tcp_fin_timeout",
        "net.ipv4.tcp_keepalive_time",
        "net.ipv4.tcp_keepalive_probes",
        "net.ipv4.tcp_keepalive_intvl",
        "net.ipv4.icmp_ratelimit",
    };

    for (num_params) |num_param| {
        if (mem.eql(u8, param, num_param)) {
            const num = std.fmt.parseInt(u64, value, 10) catch return error.InvalidValue;

            // Reasonable bounds checking
            if (num > 2147483647) { // Max int32
                return error.InvalidValue;
            }
            return;
        }
    }

    // If we got here, unknown parameter type - reject to be safe
    return error.UnknownParameterType;
}

/// Write a sysctl parameter value
pub fn setSysctl(allocator: Allocator, param: []const u8, value: []const u8) !void {
    _ = allocator; // For future use or logging

    // Validate parameter is whitelisted
    if (!isAllowedParam(param)) {
        return error.ParameterNotWhitelisted;
    }

    // Validate value format
    try validateValue(param, value);

    // Convert to filesystem path
    var path_buf: [256]u8 = undefined;
    const path = try paramToPath(param, &path_buf);

    // Open and write file
    const file = fs.openFileAbsolute(path, .{ .mode = .write_only }) catch |err| {
        std.log.err("Failed to open sysctl parameter '{s}' for writing: {}", .{param, err});
        return error.ParameterNotWritable;
    };
    defer file.close();

    // Write value (add newline for compatibility with sysctl)
    try file.writeAll(value);
    try file.writeAll("\n");
}

/// Escape a string for JSON (simple implementation for common cases)
fn escapeJsonString(allocator: Allocator, s: []const u8) ![]const u8 {
    var escaped = try std.ArrayList(u8).initCapacity(allocator, s.len);
    errdefer escaped.deinit(allocator);

    for (s) |c| {
        switch (c) {
            '\\' => try escaped.appendSlice(allocator, "\\\\"),
            '"' => try escaped.appendSlice(allocator, "\\\""),
            '\n' => try escaped.appendSlice(allocator, "\\n"),
            '\r' => try escaped.appendSlice(allocator, "\\r"),
            '\t' => try escaped.appendSlice(allocator, "\\t"),
            else => try escaped.append(allocator, c),
        }
    }

    return try escaped.toOwnedSlice(allocator);
}

/// Handle sysctl operation from JSON request
/// Returns JSON response as allocated string
pub fn handleSysctlOperation(allocator: Allocator, operation: []const u8, param: []const u8, value: ?[]const u8) ![]const u8 {
    if (mem.eql(u8, operation, "get")) {
        const result = getSysctl(allocator, param) catch |err| {
            // Build error response
            const error_msg = switch (err) {
                error.ParameterNotWhitelisted => "Parameter not in whitelist",
                error.ParameterNotFound => "Parameter not found",
                else => "Failed to read parameter",
            };

            return std.fmt.allocPrint(allocator,
                "{{\"error\": \"{s}: {s}\"}}",
                .{error_msg, param}
            );
        };
        defer allocator.free(result);

        // Escape value for JSON
        const escaped_value = try escapeJsonString(allocator, result);
        defer allocator.free(escaped_value);

        // Build success response
        return std.fmt.allocPrint(allocator,
            "{{\"sysctl\": {{\"parameter\": \"{s}\", \"value\": \"{s}\"}}}}",
            .{param, escaped_value}
        );

    } else if (mem.eql(u8, operation, "set")) {
        const val = value orelse return error.MissingValue;

        setSysctl(allocator, param, val) catch |err| {
            // Build error response
            const error_msg = switch (err) {
                error.ParameterNotWhitelisted => "Parameter not in whitelist",
                error.InvalidValue => "Invalid value for parameter",
                error.ParameterNotWritable => "Parameter not writable",
                error.UnknownParameterType => "Unknown parameter type",
                else => "Failed to write parameter",
            };

            return std.fmt.allocPrint(allocator,
                "{{\"error\": \"{s}: {s}\"}}",
                .{error_msg, param}
            );
        };

        // Build success response
        return std.fmt.allocPrint(allocator,
            "{{\"sysctl\": {{\"parameter\": \"{s}\", \"value\": \"{s}\", \"status\": \"ok\"}}}}",
            .{param, val}
        );

    } else {
        return std.fmt.allocPrint(allocator,
            "{{\"error\": \"Unknown operation: {s}\"}}",
            .{operation}
        );
    }
}
