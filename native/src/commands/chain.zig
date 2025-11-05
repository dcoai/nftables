const std = @import("std");
const protocol = @import("../protocol.zig");
const resources = @import("../resources.zig");
const libnftnl = @import("../libnftnl.zig");
const netlink_errors = @import("../netlink_errors.zig");
const common = @import("common.zig");

// Compile-time attribute maps for chain operations
const chain_attr_str_map = std.StaticStringMap(u16).initComptime(.{
    .{ "name", libnftnl.NFTNL_CHAIN_NAME },
    .{ "table", libnftnl.NFTNL_CHAIN_TABLE },
    .{ "type", libnftnl.NFTNL_CHAIN_TYPE },
});

const chain_attr_u32_map = std.StaticStringMap(u16).initComptime(.{
    .{ "family", libnftnl.NFTNL_CHAIN_FAMILY },
    .{ "hooknum", libnftnl.NFTNL_CHAIN_HOOKNUM },
    .{ "prio", libnftnl.NFTNL_CHAIN_PRIO },
    .{ "policy", libnftnl.NFTNL_CHAIN_POLICY },
});

const chain_attr_u8_map = std.StaticStringMap(u16).initComptime(.{
    .{ "policy", libnftnl.NFTNL_CHAIN_POLICY },
});

pub fn handleChainAlloc(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    const chain = libnftnl.chainAlloc() catch |err| {
        const error_msg = try std.fmt.allocPrint(allocator, "chain_alloc_failed: {}", .{err});
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    const resource_id = try resource_mgr.allocate(.chain, chain);

    return common.okValueResponse(allocator, request.req_id, resource_id);
}

pub fn handleChainFree(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id]
    if (request.args.items.len != 1) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "chain_free: expected 1 arg"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "chain_free: invalid resource_id"));
    };

    // Get the resource
    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "chain_free: resource not found"));
    };

    if (resource.type != .chain) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "chain_free: not a chain resource"));
    }

    // Free the resource (this calls chainFree internally and removes from tracking)
    resource_mgr.free(resource_id) catch {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "chain_free: failed to free resource"));
    };

    return common.okResponse(allocator, request.req_id);
}

pub fn handleChainSetStr(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSetStr(allocator, request, resource_mgr, .{
        .resource_type = .chain,
        .attr_map = &chain_attr_str_map,
        .set_fn = libnftnl.chainSetStr,
        .function_name = "chain_set_str",
    });
}

pub fn handleChainSetU32(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSetU32(allocator, request, resource_mgr, .{
        .resource_type = .chain,
        .attr_map = &chain_attr_u32_map,
        .set_fn = libnftnl.chainSetU32,
        .function_name = "chain_set_u32",
    });
}

pub fn handleChainSetU8(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSetU8(allocator, request, resource_mgr, .{
        .resource_type = .chain,
        .attr_map = &chain_attr_u8_map,
        .set_fn = libnftnl.chainSetU8,
        .function_name = "chain_set_u8",
    });
}

pub fn handleChainGetStr(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleGetStr(allocator, request, resource_mgr, .{
        .resource_type = .chain,
        .attr_map = &chain_attr_str_map,
        .get_fn = libnftnl.chainGetStr,
        .function_name = "chain_get_str",
    });
}

pub fn handleChainGetU32(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleGetU32(allocator, request, resource_mgr, .{
        .resource_type = .chain,
        .attr_map = &chain_attr_u32_map,
        .get_fn = libnftnl.chainGetU32,
        .function_name = "chain_get_u32",
    });
}

// Rule operations

pub fn handleChainSendToKernel(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSendToKernel(allocator, request, resource_mgr, .{
        .resource_type = .chain,
        .msg_type_new = libnftnl.NFT_MSG_NEWCHAIN,
        .msg_type_del = libnftnl.NFT_MSG_DELCHAIN,
        .family_attr = libnftnl.NFTNL_CHAIN_FAMILY,
        .get_family_fn = libnftnl.chainGetU32,
        .build_payload_fn = libnftnl.chainNlmsgBuildPayload,
        .function_name = "chain_send_to_kernel",
    });
}

