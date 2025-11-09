const std = @import("std");
const libnftables = @import("libnftables.zig");
const capabilities = @import("capabilities.zig");
const sysctl = @import("sysctl.zig");

/// Check if JSON message is a sysctl operation (vs nftables operation)
/// Returns true if message contains {"sysctl": ...}
fn isSysctlMessage(json: []const u8) bool {
    // Simple check: look for "sysctl" key in JSON
    // This is a lightweight check before full JSON parsing
    return std.mem.indexOf(u8, json, "\"sysctl\"") != null;
}

/// Parse and handle sysctl JSON message
/// Expected format: {"sysctl": {"operation": "get|set", "parameter": "...", "value": "..."}}
fn handleSysctlMessage(allocator: std.mem.Allocator, json: []const u8) ![]const u8 {
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        json,
        .{}
    );
    defer parsed.deinit();

    const root = parsed.value.object;
    const sysctl_obj = root.get("sysctl") orelse return error.MissingSysctlKey;

    if (sysctl_obj != .object) return error.InvalidSysctlFormat;

    const operation_value = sysctl_obj.object.get("operation") orelse return error.MissingOperation;
    const param_value = sysctl_obj.object.get("parameter") orelse return error.MissingParameter;

    if (operation_value != .string) return error.InvalidOperation;
    if (param_value != .string) return error.InvalidParameter;

    const operation = operation_value.string;
    const parameter = param_value.string;

    const value = if (sysctl_obj.object.get("value")) |v|
        if (v == .string) v.string else null
    else
        null;

    return try sysctl.handleSysctlOperation(allocator, operation, parameter, value);
}

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

    // Main loop: Read JSON packets, execute, respond with JSON
    while (true) {
        // Read packet (JSON command)
        const json_cmd = readPacket(allocator, stdin_file) catch |err| {
            if (err == error.EndOfStream) {
                // Clean shutdown when stdin closes
                break;
            }
            std.debug.print("ERROR: Failed to read packet: {}\n", .{err});
            return err;
        };
        defer allocator.free(json_cmd);

        // Detect message type and route accordingly
        const response_json = if (isSysctlMessage(json_cmd)) blk: {
            // Handle sysctl operation
            const result = handleSysctlMessage(allocator, json_cmd) catch |err| {
                const error_msg = try std.fmt.allocPrint(allocator,
                    "{{\"error\": \"Sysctl operation failed: {}\"}}",
                    .{err}
                );
                break :blk error_msg;
            };
            break :blk result;
        } else blk: {
            // Handle nftables operation (existing code)
            // Null-terminate for C string (libnftables expects null-terminated strings)
            const json_cmd_z = try allocator.dupeZ(u8, json_cmd);
            defer allocator.free(json_cmd_z);

            // Execute command via libnftables
            const result = libnftables.runCmdFromBuffer(ctx, json_cmd_z.ptr);

            // Get output or error buffer
            const nft_response = if (result == 0) response_blk: {
                // Success - get output buffer
                if (libnftables.ctxGetOutputBuffer(ctx)) |buf| {
                    break :response_blk std.mem.span(buf);
                } else {
                    // No output (e.g., for add/delete commands with no echo)
                    break :response_blk "";
                }
            } else response_blk: {
                // Error - get error buffer
                if (libnftables.ctxGetErrorBuffer(ctx)) |buf| {
                    break :response_blk std.mem.span(buf);
                } else {
                    // No error message available
                    break :response_blk "{\"error\": {\"code\": -1, \"message\": \"Unknown error\"}}";
                }
            };

            break :blk nft_response;
        };

        // Send JSON response back to Elixir
        try writePacket(stdout_file, response_json);

        // Clear buffers for next iteration (MUST happen AFTER sending response)
        // The response pointers are only valid while buffers are active
        if (!isSysctlMessage(json_cmd)) {
            _ = libnftables.ctxUnbufferOutput(ctx);
            _ = libnftables.ctxUnbufferError(ctx);
            _ = libnftables.ctxBufferOutput(ctx);
            _ = libnftables.ctxBufferError(ctx);
        }

        // Free sysctl response if allocated
        if (isSysctlMessage(json_cmd)) {
            allocator.free(response_json);
        }
    }
}
