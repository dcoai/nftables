const std = @import("std");
const protocol = @import("../protocol.zig");
const resources = @import("../resources.zig");
const libnftnl = @import("../libnftnl.zig");
const netlink_errors = @import("../netlink_errors.zig");
const common = @import("common.zig");

pub fn handleBatchAlloc(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [page_size, max_pages]
    if (request.args.items.len != 2) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "batch_alloc: expected 2 args (page_size, max_pages)"));
    }

    const page_size = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "batch_alloc: invalid page_size"));
    };

    const max_pages = request.args.items[1].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "batch_alloc: invalid max_pages"));
    };

    const batch = libnftnl.batchAlloc(@intCast(page_size), @intCast(max_pages)) catch |err| {
        const error_msg = try std.fmt.allocPrint(allocator, "batch_alloc_failed: {}", .{err});
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    const resource_id = try resource_mgr.allocate(.batch, batch);

    return common.okValueResponse(allocator, request.req_id, resource_id);
}

pub fn handleBatchFree(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id]
    if (request.args.items.len != 1) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "batch_free: expected 1 arg"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "batch_free: invalid resource_id"));
    };

    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "batch_free: resource not found"));
    };

    if (resource.type != .batch) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "batch_free: not a batch resource"));
    }

    resource_mgr.free(resource_id) catch {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "batch_free: failed to free resource"));
    };

    return common.okResponse(allocator, request.req_id);
}

// Netlink socket operations

