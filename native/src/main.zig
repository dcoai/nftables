const std = @import("std");
const protocol = @import("protocol.zig");
const commands = @import("commands.zig");
const capabilities = @import("capabilities.zig");
const resources = @import("resources.zig");

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

    // Log successful permission check
    std.debug.print("info: Security check passed - permissions: {o:0>3}\n", .{mode & 0o777});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // SECURITY: Check executable permissions before doing anything else
    try checkExecutablePermissions();

    // Set up capabilities (CAP_NET_ADMIN)
    try capabilities.setup();
    defer capabilities.teardown();

    // Initialize resource manager
    var resource_mgr = resources.ResourceManager.init(allocator);
    defer resource_mgr.deinit();

    // Get stdin and stdout
    const stdin_file = std.fs.File{ .handle = std.posix.STDIN_FILENO };
    const stdout_file = std.fs.File{ .handle = std.posix.STDOUT_FILENO };

    std.debug.print("libnf_ex port initialized and ready\n", .{});

    // Main event loop - read from stdin, write to stdout
    while (true) {
        // Read request from stdin
        var request = protocol.readMessage(allocator, stdin_file) catch |err| {
            switch (err) {
                error.EndOfStream => {
                    std.debug.print("Port received EOF, shutting down\n", .{});
                    std.debug.print("Active resources at shutdown: {}\n", .{resource_mgr.count()});
                    break;
                },
                else => {
                    std.debug.print("Error reading message: {}\n", .{err});
                    continue;
                },
            }
        };
        defer request.deinit();

        // Dispatch command and generate response
        const response = commands.dispatch(allocator, request, &resource_mgr) catch |err| blk: {
            // If dispatch fails, send error response
            const error_msg = try std.fmt.allocPrint(allocator, "dispatch_error: {}", .{err});
            break :blk protocol.Response{
                .allocator = allocator,
                .req_id = request.req_id,
                .payload = .{ .error_msg = error_msg },
            };
        };
        defer response.deinit();

        // Write response to stdout
        protocol.writeMessage(stdout_file, response) catch |err| {
            std.debug.print("Error writing response: {}\n", .{err});
            continue;
        };
    }
}
