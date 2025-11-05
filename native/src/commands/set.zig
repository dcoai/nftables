const std = @import("std");
const protocol = @import("../protocol.zig");
const resources = @import("../resources.zig");
const libnftnl = @import("../libnftnl.zig");
const netlink_errors = @import("../netlink_errors.zig");
const common = @import("common.zig");

// Compile-time attribute maps for set operations
const set_attr_str_map = std.StaticStringMap(u16).initComptime(.{
    .{ "name", libnftnl.NFTNL_SET_NAME },
    .{ "table", libnftnl.NFTNL_SET_TABLE },
});

const set_attr_u32_map = std.StaticStringMap(u16).initComptime(.{
    .{ "family", libnftnl.NFTNL_SET_FAMILY },
    .{ "key_type", libnftnl.NFTNL_SET_KEY_TYPE },
    .{ "key_len", libnftnl.NFTNL_SET_KEY_LEN },
    .{ "data_type", libnftnl.NFTNL_SET_DATA_TYPE },
    .{ "data_len", libnftnl.NFTNL_SET_DATA_LEN },
    .{ "flags", libnftnl.NFTNL_SET_FLAGS },
    .{ "id", libnftnl.NFTNL_SET_ID },
    .{ "policy", libnftnl.NFTNL_SET_POLICY },
    .{ "desc_size", libnftnl.NFTNL_SET_DESC_SIZE },
});

pub fn handleSetAlloc(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // No arguments expected
    if (request.args.items.len != 0) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_alloc: expected 0 args"));
    }

    const set = libnftnl.setAlloc() catch |err| {
        const error_msg = try std.fmt.allocPrint(allocator, "set_alloc_failed: {}", .{err});
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    const resource_id = try resource_mgr.allocate(.set, set);

    return common.okValueResponse(allocator, request.req_id, resource_id);
}

pub fn handleSetFree(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id]
    if (request.args.items.len != 1) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_free: expected 1 arg"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_free: invalid resource_id"));
    };

    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_free: resource not found"));
    };

    if (resource.type != .set) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_free: not a set resource"));
    }

    resource_mgr.free(resource_id) catch {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_free: failed to free resource"));
    };

    return common.okResponse(allocator, request.req_id);
}

pub fn handleSetSetStr(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSetStr(allocator, request, resource_mgr, .{
        .resource_type = .set,
        .attr_map = &set_attr_str_map,
        .set_fn = libnftnl.setSetStr,
        .function_name = "set_set_str",
    });
}

pub fn handleSetSetU32(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSetU32(allocator, request, resource_mgr, .{
        .resource_type = .set,
        .attr_map = &set_attr_u32_map,
        .set_fn = libnftnl.setSetU32,
        .function_name = "set_set_u32",
    });
}

pub fn handleSetSendToKernel(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSendToKernel(allocator, request, resource_mgr, .{
        .resource_type = .set,
        .msg_type_new = libnftnl.NFT_MSG_NEWSET,
        .msg_type_del = libnftnl.NFT_MSG_DELSET,
        .family_attr = libnftnl.NFTNL_SET_FAMILY,
        .get_family_fn = libnftnl.setGetU32,
        .build_payload_fn = libnftnl.setNlmsgBuildPayload,
        .function_name = "set_send_to_kernel",
    });
}

