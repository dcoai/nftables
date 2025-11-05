const std = @import("std");
const protocol = @import("../protocol.zig");
const common = @import("common.zig");

pub fn handlePing(allocator: std.mem.Allocator, request: protocol.Request) !protocol.Response {
    // Simple ping/pong - just return :ok
    return common.okResponse(allocator, request.req_id);
}

pub fn handleCheckCapabilities(allocator: std.mem.Allocator, request: protocol.Request) !protocol.Response {
    const capabilities = @import("../capabilities.zig");

    // Check if CAP_NET_ADMIN is active
    const has_cap = capabilities.hasNetAdmin();

    // Return boolean value (1 for true, 0 for false)
    const value: u64 = if (has_cap) 1 else 0;
    return common.okValueResponse(allocator, request.req_id, value);
}
