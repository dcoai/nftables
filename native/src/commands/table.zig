const std = @import("std");
const protocol = @import("../protocol.zig");
const resources = @import("../resources.zig");
const libnftnl = @import("../libnftnl.zig");
const netlink_errors = @import("../netlink_errors.zig");
const common = @import("common.zig");

// Compile-time attribute maps for table operations
const table_attr_str_map = std.StaticStringMap(u16).initComptime(.{
    .{ "name", libnftnl.NFTNL_TABLE_NAME },
});

const table_attr_u32_map = std.StaticStringMap(u16).initComptime(.{
    .{ "family", libnftnl.NFTNL_TABLE_FAMILY },
    .{ "flags", libnftnl.NFTNL_TABLE_FLAGS },
});

pub fn handleTableAlloc(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Allocate an nftables table object
    const table = libnftnl.tableAlloc() catch |err| {
        const error_msg = try std.fmt.allocPrint(allocator, "table_alloc_failed: {}", .{err});
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    // Track the resource
    const resource_id = try resource_mgr.allocate(.table, table);

    return common.okValueResponse(allocator, request.req_id, resource_id);
}

pub fn handleTableFree(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id]
    if (request.args.items.len != 1) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "table_free: expected 1 arg"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "table_free: invalid resource_id"));
    };

    // Get the resource
    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "table_free: resource not found"));
    };

    if (resource.type != .table) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "table_free: not a table resource"));
    }

    // Free the resource (this calls tableFree internally and removes from tracking)
    resource_mgr.free(resource_id) catch {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "table_free: failed to free resource"));
    };

    return common.okResponse(allocator, request.req_id);
}

pub fn handleTableSetStr(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSetStr(allocator, request, resource_mgr, .{
        .resource_type = .table,
        .attr_map = &table_attr_str_map,
        .set_fn = libnftnl.tableSetStr,
        .function_name = "table_set_str",
    });
}

pub fn handleTableSetU32(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSetU32(allocator, request, resource_mgr, .{
        .resource_type = .table,
        .attr_map = &table_attr_u32_map,
        .set_fn = libnftnl.tableSetU32,
        .function_name = "table_set_u32",
    });
}

pub fn handleTableGetStr(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleGetStr(allocator, request, resource_mgr, .{
        .resource_type = .table,
        .attr_map = &table_attr_str_map,
        .get_fn = libnftnl.tableGetStr,
        .function_name = "table_get_str",
    });
}

pub fn handleTableGetU32(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleGetU32(allocator, request, resource_mgr, .{
        .resource_type = .table,
        .attr_map = &table_attr_u32_map,
        .get_fn = libnftnl.tableGetU32,
        .function_name = "table_get_u32",
    });
}

// Chain operations

pub fn handleTableSendToKernel(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSendToKernel(allocator, request, resource_mgr, .{
        .resource_type = .table,
        .msg_type_new = libnftnl.NFT_MSG_NEWTABLE,
        .msg_type_del = libnftnl.NFT_MSG_DELTABLE,
        .family_attr = libnftnl.NFTNL_TABLE_FAMILY,
        .get_family_fn = libnftnl.tableGetU32,
        .build_payload_fn = libnftnl.tableNlmsgBuildPayload,
        .function_name = "table_send_to_kernel",
    });
}

