const std = @import("std");
const libnftables = @import("libnftables.zig");
const capabilities = @import("capabilities.zig");

// C bindings for ei.h (Erlang Interface)
const c = @cImport({
    @cInclude("ei.h");
});

/// Format detection for incoming requests
const Format = enum {
    json_raw, // No prefix, backward compatible (default)
    json_prefixed, // "JSN:" prefix (explicit JSON)
    etf, // "ETF:" prefix (Erlang Term Format)
};

/// Security check: Verify that the executable has restricted permissions.
/// For security, the executable must NOT have world-readable, world-writable,
/// or world-executable permissions (mode must end in 0, e.g., 750, 700).
/// This prevents unauthorized users from executing a capability-enabled binary.
fn checkExecutablePermissions() !void {
    // Get the path to the current executable
    var path_buf: [std.posix.PATH_MAX]u8 = undefined;
    const exe_path = try std.fs.selfExePath(&path_buf);

    // Stat the executable to get its permissions
    const stat = try std.fs.cwd().statFile(exe_path);
    const mode = stat.mode;

    // Check if "other" permissions are set (last 3 bits)
    // mode & 0o7 extracts the last octal digit (rwx for "other")
    const other_perms = mode & 0o7;

    if (other_perms != 0) {
        std.debug.print(
            \\
            \\SECURITY ERROR: Executable has world permissions enabled!
            \\
            \\Current permissions: {o:0>3}
            \\
            \\This executable has CAP_NET_ADMIN capability and MUST NOT be
            \\world-readable, world-writable, or world-executable.
            \\
            \\To fix, run:
            \\  chmod 750 {s}
            \\  # or
            \\  chmod 700 {s}
            \\
            \\The mode must end in 0 (no permissions for "other").
            \\Access should be controlled via user/group ownership.
            \\
            \\Refusing to start for security reasons.
            \\
        , .{ mode & 0o777, exe_path, exe_path });
        return error.InsecurePermissions;
    }
}

/// Read exactly n bytes from file
fn readExact(file: std.fs.File, buffer: []u8) !void {
    var total_read: usize = 0;
    while (total_read < buffer.len) {
        const n = try file.read(buffer[total_read..]);
        if (n == 0) {
            return error.EndOfStream;
        }
        total_read += n;
    }
}

/// Read a packet-length-prefixed message from stdin
/// Returns allocated buffer containing the message
fn readPacket(allocator: std.mem.Allocator, file: std.fs.File) ![]u8 {
    // Read 4-byte big-endian length prefix
    var len_buf: [4]u8 = undefined;
    try readExact(file, &len_buf);

    const len = std.mem.readInt(u32, &len_buf, .big);

    // Sanity check: reject unreasonably large packets (> 10MB)
    if (len > 10 * 1024 * 1024) {
        return error.PacketTooLarge;
    }

    // Allocate buffer and read message
    const buffer = try allocator.alloc(u8, len);
    errdefer allocator.free(buffer);

    try readExact(file, buffer);

    return buffer;
}

/// Write a packet-length-prefixed message to stdout
fn writePacket(file: std.fs.File, data: []const u8) !void {
    // Write 4-byte big-endian length prefix
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try file.writeAll(&len_buf);

    // Write message data
    try file.writeAll(data);
}

/// Detect format from packet data
fn detectFormat(packet: []const u8) Format {
    if (packet.len >= 4) {
        if (std.mem.eql(u8, packet[0..4], "ETF:")) {
            return .etf;
        } else if (std.mem.eql(u8, packet[0..4], "JSN:")) {
            return .json_prefixed;
        }
    }
    return .json_raw; // Default to JSON for backward compatibility
}

/// Write JSON-escaped string
fn writeJsonString(writer: anytype, str: []const u8) !void {
    try writer.writeByte('"');
    for (str) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            '\x08' => try writer.writeAll("\\b"),
            '\x0C' => try writer.writeAll("\\f"),
            else => {
                if (byte < 0x20) {
                    // Control characters - escape as \uXXXX
                    try writer.print("\\u{x:0>4}", .{byte});
                } else {
                    try writer.writeByte(byte);
                }
            },
        }
    }
    try writer.writeByte('"');
}

/// Recursively convert ETF term to JSON
/// Writes JSON directly to the writer
fn etfTermToJson(allocator: std.mem.Allocator, etf_data: []const u8, index: *c_int, writer: anytype) !void {
    var term_type: c_int = undefined;
    var term_size: c_int = undefined;

    // Get term type and size
    if (c.ei_get_type(@ptrCast(etf_data.ptr), index, &term_type, &term_size) != 0) {
        return error.ETFDecodeError;
    }

    switch (term_type) {
        c.ERL_MAP_EXT => {
            // Map: {"key": value, ...}
            var arity: c_int = undefined;
            if (c.ei_decode_map_header(@ptrCast(etf_data.ptr), index, &arity) != 0) {
                return error.ETFDecodeError;
            }

            try writer.writeByte('{');
            var i: c_int = 0;
            while (i < arity) : (i += 1) {
                if (i > 0) try writer.writeByte(',');

                // Decode key (should be a string/atom)
                try etfTermToJson(allocator, etf_data, index, writer);
                try writer.writeByte(':');

                // Decode value (any type)
                try etfTermToJson(allocator, etf_data, index, writer);
            }
            try writer.writeByte('}');
        },

        c.ERL_LIST_EXT => {
            // List: [elem1, elem2, ...]
            var arity: c_int = undefined;
            if (c.ei_decode_list_header(@ptrCast(etf_data.ptr), index, &arity) != 0) {
                return error.ETFDecodeError;
            }

            try writer.writeByte('[');
            var i: c_int = 0;
            while (i < arity) : (i += 1) {
                if (i > 0) try writer.writeByte(',');
                try etfTermToJson(allocator, etf_data, index, writer);
            }

            // Erlang lists have a tail - usually NIL_EXT
            // Decode the tail (should be empty list)
            var tail_type: c_int = undefined;
            var tail_size: c_int = undefined;
            if (c.ei_get_type(@ptrCast(etf_data.ptr), index, &tail_type, &tail_size) != 0) {
                return error.ETFDecodeError;
            }

            if (tail_type != c.ERL_NIL_EXT) {
                // Improper list - not supported in JSON
                std.debug.print("ERROR: Improper list tail type: {}\n", .{tail_type});
                return error.UnsupportedETFType;
            }

            // Skip the NIL tail
            index.* += 1;

            try writer.writeByte(']');
        },

        c.ERL_NIL_EXT => {
            // Empty list: []
            index.* += 1; // Skip the NIL byte
            try writer.writeAll("[]");
        },

        c.ERL_BINARY_EXT => {
            // Binary (string)
            const buffer = try allocator.alloc(u8, @intCast(term_size));
            defer allocator.free(buffer);

            var actual_size: c_long = @intCast(term_size);
            if (c.ei_decode_binary(@ptrCast(etf_data.ptr), index, buffer.ptr, &actual_size) != 0) {
                return error.ETFDecodeError;
            }

            try writeJsonString(writer, buffer[0..@intCast(actual_size)]);
        },

        c.ERL_STRING_EXT => {
            // String (optimized encoding for byte lists)
            const buffer = try allocator.alloc(u8, @intCast(term_size));
            defer allocator.free(buffer);

            if (c.ei_decode_string(@ptrCast(etf_data.ptr), index, @ptrCast(buffer.ptr)) != 0) {
                return error.ETFDecodeError;
            }

            try writeJsonString(writer, buffer[0..@intCast(term_size)]);
        },

        c.ERL_ATOM_UTF8_EXT, c.ERL_SMALL_ATOM_UTF8_EXT, c.ERL_ATOM_EXT, c.ERL_SMALL_ATOM_EXT => {
            // Atom - convert to string, special case for nil/true/false
            var atom_buffer: [256]u8 = undefined;
            if (c.ei_decode_atom(@ptrCast(etf_data.ptr), index, @ptrCast(&atom_buffer)) != 0) {
                return error.ETFDecodeError;
            }

            const atom_str = std.mem.sliceTo(&atom_buffer, 0);

            // Special cases for JSON literals
            if (std.mem.eql(u8, atom_str, "nil") or std.mem.eql(u8, atom_str, "null")) {
                try writer.writeAll("null");
            } else if (std.mem.eql(u8, atom_str, "true")) {
                try writer.writeAll("true");
            } else if (std.mem.eql(u8, atom_str, "false")) {
                try writer.writeAll("false");
            } else {
                // Regular atom -> JSON string
                try writeJsonString(writer, atom_str);
            }
        },

        c.ERL_SMALL_INTEGER_EXT, c.ERL_INTEGER_EXT => {
            // Integer
            var value: c_long = undefined;
            if (c.ei_decode_long(@ptrCast(etf_data.ptr), index, &value) != 0) {
                return error.ETFDecodeError;
            }
            try writer.print("{d}", .{value});
        },

        c.ERL_FLOAT_EXT => {
            // Float
            var value: f64 = undefined;
            if (c.ei_decode_double(@ptrCast(etf_data.ptr), index, &value) != 0) {
                return error.ETFDecodeError;
            }
            try writer.print("{d}", .{value});
        },

        c.ERL_SMALL_TUPLE_EXT, c.ERL_LARGE_TUPLE_EXT => {
            // Tuple - convert to JSON array
            var arity: c_int = undefined;
            if (c.ei_decode_tuple_header(@ptrCast(etf_data.ptr), index, &arity) != 0) {
                return error.ETFDecodeError;
            }

            try writer.writeByte('[');
            var i: c_int = 0;
            while (i < arity) : (i += 1) {
                if (i > 0) try writer.writeByte(',');
                try etfTermToJson(allocator, etf_data, index, writer);
            }
            try writer.writeByte(']');
        },

        else => {
            // Unsupported type
            std.debug.print("ERROR: Unsupported ETF term type: {}\n", .{term_type});
            return error.UnsupportedETFType;
        },
    }
}

/// Decode ETF term and convert to JSON string
/// Caller owns returned slice
fn etfToJson(allocator: std.mem.Allocator, etf_data: []const u8) ![]const u8 {
    // ETF format: [version:1, data...]
    // ei library functions expect index to start at 0 (before version byte)
    if (etf_data.len == 0) {
        return error.EmptyETFData;
    }

    var index: c_int = 0;
    var version: c_int = undefined;

    // Decode and skip version byte
    if (c.ei_decode_version(@ptrCast(etf_data.ptr), &index, &version) != 0) {
        std.debug.print("ERROR: Failed to decode ETF version. First byte: {}\n", .{etf_data[0]});
        return error.InvalidETFVersion;
    }

    // ETF version magic is always 131 (0x83)
    if (version != 131) {
        std.debug.print("ERROR: Wrong ETF version: {} (expected 131)\n", .{version});
        return error.InvalidETFVersion;
    }

    // Build JSON string using ArrayList
    var json: std.ArrayList(u8) = .empty;
    defer json.deinit(allocator);

    const writer = json.writer(allocator);

    // Recursively convert ETF term to JSON
    try etfTermToJson(allocator, etf_data, &index, writer);

    // Return owned slice
    return try json.toOwnedSlice(allocator);
}

/// Encode JSON response as ETF binary
/// Caller owns returned slice
fn jsonToEtf(allocator: std.mem.Allocator, json_data: []const u8) ![]const u8 {
    // Calculate required buffer size
    // ETF format: [version:1, binary_ext:1, length:4, data:N]
    const required_size = 1 + 1 + 4 + json_data.len;

    const buffer = try allocator.alloc(u8, required_size + 100); // Extra space for ei overhead
    errdefer allocator.free(buffer);

    var index: c_int = 0;

    // Encode version byte
    if (c.ei_encode_version(@ptrCast(buffer.ptr), &index) != 0) {
        return error.ETFEncodeError;
    }

    // Encode binary (JSON string)
    if (c.ei_encode_binary(@ptrCast(buffer.ptr), &index, @ptrCast(json_data.ptr), @intCast(json_data.len)) != 0) {
        return error.ETFEncodeError;
    }

    // Return only the used portion
    const result = try allocator.dupe(u8, buffer[0..@intCast(index)]);
    allocator.free(buffer);
    return result;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // SECURITY: Check executable permissions before doing anything else
    try checkExecutablePermissions();

    // Setup capabilities (checks CAP_NET_ADMIN)
    try capabilities.setup();

    // Create nftables context
    const ctx = libnftables.ctxNew(libnftables.NFT_CTX_DEFAULT) orelse {
        std.debug.print("ERROR: Failed to create nftables context\n", .{});
        return error.ContextCreationFailed;
    };
    defer libnftables.ctxFree(ctx);

    // Enable buffered output and error
    // This captures output instead of writing directly to stdout/stderr
    _ = libnftables.ctxBufferOutput(ctx);
    _ = libnftables.ctxBufferError(ctx);

    // Set JSON output format and include handles
    libnftables.ctxOutputSetFlags(
        ctx,
        libnftables.NFT_CTX_OUTPUT_JSON | libnftables.NFT_CTX_OUTPUT_HANDLE,
    );

    // Get stdin/stdout
    const stdin_file = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout_file = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    // Main loop: Read packets, detect format, execute, respond in same format
    while (true) {
        // Read packet
        const packet = readPacket(allocator, stdin_file) catch |err| {
            if (err == error.EndOfStream) {
                // Clean shutdown when stdin closes
                break;
            }
            std.debug.print("ERROR: Failed to read packet: {}\n", .{err});
            return err;
        };
        defer allocator.free(packet);

        // Detect format
        const format = detectFormat(packet);

        // Extract payload (strip prefix if present)
        const payload = switch (format) {
            .json_raw => packet,
            .json_prefixed => packet[4..], // Skip "JSN:"
            .etf => packet[4..], // Skip "ETF:"
        };

        // Convert to JSON command based on format
        const json_cmd = switch (format) {
            .json_raw, .json_prefixed => payload, // Already JSON
            .etf => etfToJson(allocator, payload) catch |err| {
                std.debug.print("ERROR: Failed to convert ETF to JSON: {}\n", .{err});

                // Send error response (default to unprefixed JSON for errors)
                const error_json = "{\"error\": \"ETF decode failed\"}";
                try writePacket(stdout_file, error_json);
                continue;
            },
        };
        defer if (format == .etf) allocator.free(json_cmd);

        // Null-terminate for C string (libnftables expects null-terminated strings)
        const json_cmd_z = try allocator.dupeZ(u8, json_cmd);
        defer allocator.free(json_cmd_z);

        // Execute command via libnftables
        const result = libnftables.runCmdFromBuffer(ctx, json_cmd_z.ptr);

        // Get output or error buffer
        const response_json = if (result == 0) blk: {
            // Success - get output buffer
            if (libnftables.ctxGetOutputBuffer(ctx)) |buf| {
                break :blk std.mem.span(buf);
            } else {
                // No output (e.g., for add/delete commands with no echo)
                break :blk "";
            }
        } else blk: {
            // Error - get error buffer
            if (libnftables.ctxGetErrorBuffer(ctx)) |buf| {
                break :blk std.mem.span(buf);
            } else {
                // No error message available
                break :blk "{\"error\": {\"code\": -1, \"message\": \"Unknown error\"}}";
            }
        };

        // Prepare response in same format as request
        const response = switch (format) {
            .json_raw => blk: {
                // No prefix for backward compatibility
                break :blk response_json;
            },
            .json_prefixed => blk: {
                // Prepend "JSN:" prefix
                const prefixed = try std.fmt.allocPrint(allocator, "JSN:{s}", .{response_json});
                break :blk prefixed;
            },
            .etf => blk: {
                // Convert JSON to ETF and prepend "ETF:" prefix
                const response_etf = jsonToEtf(allocator, response_json) catch |err| {
                    std.debug.print("ERROR: Failed to convert JSON to ETF: {}\n", .{err});

                    // Fall back to JSON error (no prefix)
                    const error_json = "{\"error\": \"ETF encode failed\"}";
                    try writePacket(stdout_file, error_json);

                    // Clear buffers for next iteration
                    _ = libnftables.ctxUnbufferOutput(ctx);
                    _ = libnftables.ctxUnbufferError(ctx);
                    _ = libnftables.ctxBufferOutput(ctx);
                    _ = libnftables.ctxBufferError(ctx);
                    continue;
                };
                // DON'T free response_etf yet - will be concatenated with prefix

                // Manually concatenate prefix + ETF data
                const prefix = "ETF:";
                const total_len = prefix.len + response_etf.len;

                const prefixed = try allocator.alloc(u8, total_len);
                errdefer {
                    allocator.free(prefixed);
                    allocator.free(response_etf);
                }

                // Copy prefix and ETF data in one go
                @memcpy(prefixed[0..prefix.len], prefix);
                @memcpy(prefixed[prefix.len..], response_etf);

                // Now free response_etf before returning
                allocator.free(response_etf);

                break :blk prefixed;
            },
        };

        // Free prefixed responses at end of loop iteration
        defer if (format == .json_prefixed or format == .etf) {
            allocator.free(response);
        };

        // Send response back to Elixir
        try writePacket(stdout_file, response);

        // Clear buffers for next iteration
        _ = libnftables.ctxUnbufferOutput(ctx);
        _ = libnftables.ctxUnbufferError(ctx);
        _ = libnftables.ctxBufferOutput(ctx);
        _ = libnftables.ctxBufferError(ctx);
    }
}
