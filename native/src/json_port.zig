const std = @import("std");
const libnftables = @import("libnftables.zig");
const capabilities = @import("capabilities.zig");

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

    // Main loop: Read commands, execute, send responses
    while (true) {
        // Read packet-length-prefixed JSON command
        const cmd_json = readPacket(allocator, stdin_file) catch |err| {
            if (err == error.EndOfStream) {
                // Clean shutdown when stdin closes
                break;
            }
            std.debug.print("ERROR: Failed to read packet: {}\n", .{err});
            return err;
        };
        defer allocator.free(cmd_json);

        // Null-terminate for C string (libnftables expects null-terminated strings)
        const cmd_json_z = try allocator.dupeZ(u8, cmd_json);
        defer allocator.free(cmd_json_z);

        // Execute command
        const result = libnftables.runCmdFromBuffer(ctx, cmd_json_z.ptr);

        // Get output or error buffer
        const response = if (result == 0) blk: {
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

        // Send response back to Elixir
        try writePacket(stdout_file, response);

        // Clear buffers for next iteration
        _ = libnftables.ctxUnbufferOutput(ctx);
        _ = libnftables.ctxUnbufferError(ctx);
        _ = libnftables.ctxBufferOutput(ctx);
        _ = libnftables.ctxBufferError(ctx);
    }
}
