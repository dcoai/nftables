const std = @import("std");
const protocol = @import("../protocol.zig");
const resources = @import("../resources.zig");
const libnftnl = @import("../libnftnl.zig");
const netlink_errors = @import("../netlink_errors.zig");
const common = @import("common.zig");

// Compile-time map for expression attribute lookups using composite keys "expr_type:attr_name"
// This provides O(1) lookup instead of O(n) if/else chains
const expr_attr_map = std.StaticStringMap(u16).initComptime(.{
    // Generic attributes (all expressions)
    .{ ":name", libnftnl.NFTNL_EXPR_NAME },

    // Payload expression
    .{ "payload:dreg", libnftnl.NFTNL_EXPR_PAYLOAD_DREG },
    .{ "payload:base", libnftnl.NFTNL_EXPR_PAYLOAD_BASE },
    .{ "payload:offset", libnftnl.NFTNL_EXPR_PAYLOAD_OFFSET },
    .{ "payload:len", libnftnl.NFTNL_EXPR_PAYLOAD_LEN },
    .{ "payload:sreg", libnftnl.NFTNL_EXPR_PAYLOAD_SREG },
    .{ "payload:csum_type", libnftnl.NFTNL_EXPR_PAYLOAD_CSUM_TYPE },
    .{ "payload:csum_offset", libnftnl.NFTNL_EXPR_PAYLOAD_CSUM_OFFSET },
    .{ "payload:flags", libnftnl.NFTNL_EXPR_PAYLOAD_FLAGS },

    // Comparison expression
    .{ "cmp:sreg", libnftnl.NFTNL_EXPR_CMP_SREG },
    .{ "cmp:op", libnftnl.NFTNL_EXPR_CMP_OP },
    .{ "cmp:data", libnftnl.NFTNL_EXPR_CMP_DATA },

    // Immediate expression
    .{ "immediate:dreg", libnftnl.NFTNL_EXPR_IMM_DREG },
    .{ "immediate:data", libnftnl.NFTNL_EXPR_IMM_DATA },
    .{ "immediate:verdict", libnftnl.NFTNL_EXPR_IMM_VERDICT },
    .{ "immediate:chain", libnftnl.NFTNL_EXPR_IMM_CHAIN },
    .{ "immediate:chain_id", libnftnl.NFTNL_EXPR_IMM_CHAIN_ID },

    // Counter expression
    .{ "counter:packets", libnftnl.NFTNL_EXPR_CTR_PACKETS },
    .{ "counter:bytes", libnftnl.NFTNL_EXPR_CTR_BYTES },

    // Meta expression
    .{ "meta:key", libnftnl.NFTNL_EXPR_META_KEY },
    .{ "meta:dreg", libnftnl.NFTNL_EXPR_META_DREG },
    .{ "meta:sreg", libnftnl.NFTNL_EXPR_META_SREG },

    // Connection tracking expression
    .{ "ct:dreg", libnftnl.NFTNL_EXPR_CT_DREG },
    .{ "ct:key", libnftnl.NFTNL_EXPR_CT_KEY },
    .{ "ct:dir", libnftnl.NFTNL_EXPR_CT_DIR },
    .{ "ct:sreg", libnftnl.NFTNL_EXPR_CT_SREG },

    // Bitwise expression
    .{ "bitwise:sreg", libnftnl.NFTNL_EXPR_BITWISE_SREG },
    .{ "bitwise:dreg", libnftnl.NFTNL_EXPR_BITWISE_DREG },
    .{ "bitwise:len", libnftnl.NFTNL_EXPR_BITWISE_LEN },
    .{ "bitwise:mask", libnftnl.NFTNL_EXPR_BITWISE_MASK },
    .{ "bitwise:xor", libnftnl.NFTNL_EXPR_BITWISE_XOR },
    .{ "bitwise:op", libnftnl.NFTNL_EXPR_BITWISE_OP },
    .{ "bitwise:data", libnftnl.NFTNL_EXPR_BITWISE_DATA },
    .{ "bitwise:sreg2", libnftnl.NFTNL_EXPR_BITWISE_SREG2 },

    // Byteorder expression
    .{ "byteorder:dreg", libnftnl.NFTNL_EXPR_BYTEORDER_DREG },
    .{ "byteorder:sreg", libnftnl.NFTNL_EXPR_BYTEORDER_SREG },
    .{ "byteorder:op", libnftnl.NFTNL_EXPR_BYTEORDER_OP },
    .{ "byteorder:len", libnftnl.NFTNL_EXPR_BYTEORDER_LEN },
    .{ "byteorder:size", libnftnl.NFTNL_EXPR_BYTEORDER_SIZE },

    // NAT expression
    .{ "nat:type", libnftnl.NFTNL_EXPR_NAT_TYPE },
    .{ "nat:family", libnftnl.NFTNL_EXPR_NAT_FAMILY },
    .{ "nat:reg_addr_min", libnftnl.NFTNL_EXPR_NAT_REG_ADDR_MIN },
    .{ "nat:reg_addr_max", libnftnl.NFTNL_EXPR_NAT_REG_ADDR_MAX },
    .{ "nat:reg_proto_min", libnftnl.NFTNL_EXPR_NAT_REG_PROTO_MIN },
    .{ "nat:reg_proto_max", libnftnl.NFTNL_EXPR_NAT_REG_PROTO_MAX },
    .{ "nat:flags", libnftnl.NFTNL_EXPR_NAT_FLAGS },

    // Lookup expression
    .{ "lookup:sreg", libnftnl.NFTNL_EXPR_LOOKUP_SREG },
    .{ "lookup:dreg", libnftnl.NFTNL_EXPR_LOOKUP_DREG },
    .{ "lookup:set", libnftnl.NFTNL_EXPR_LOOKUP_SET },
    .{ "lookup:set_id", libnftnl.NFTNL_EXPR_LOOKUP_SET_ID },
    .{ "lookup:flags", libnftnl.NFTNL_EXPR_LOOKUP_FLAGS },

    // Log expression
    .{ "log:prefix", libnftnl.NFTNL_EXPR_LOG_PREFIX },
    .{ "log:group", libnftnl.NFTNL_EXPR_LOG_GROUP },
    .{ "log:snaplen", libnftnl.NFTNL_EXPR_LOG_SNAPLEN },
    .{ "log:qthreshold", libnftnl.NFTNL_EXPR_LOG_QTHRESHOLD },
    .{ "log:level", libnftnl.NFTNL_EXPR_LOG_LEVEL },
    .{ "log:flags", libnftnl.NFTNL_EXPR_LOG_FLAGS },

    // Limit expression
    .{ "limit:rate", libnftnl.NFTNL_EXPR_LIMIT_RATE },
    .{ "limit:unit", libnftnl.NFTNL_EXPR_LIMIT_UNIT },
    .{ "limit:burst", libnftnl.NFTNL_EXPR_LIMIT_BURST },
    .{ "limit:type", libnftnl.NFTNL_EXPR_LIMIT_TYPE },
    .{ "limit:flags", libnftnl.NFTNL_EXPR_LIMIT_FLAGS },

    // Reject expression
    .{ "reject:type", libnftnl.NFTNL_EXPR_REJECT_TYPE },
    .{ "reject:code", libnftnl.NFTNL_EXPR_REJECT_CODE },

    // Queue expression
    .{ "queue:num", libnftnl.NFTNL_EXPR_QUEUE_NUM },
    .{ "queue:total", libnftnl.NFTNL_EXPR_QUEUE_TOTAL },
    .{ "queue:flags", libnftnl.NFTNL_EXPR_QUEUE_FLAGS },
    .{ "queue:sreg_qnum", libnftnl.NFTNL_EXPR_QUEUE_SREG_QNUM },

    // Masquerade expression
    .{ "masq:flags", libnftnl.NFTNL_EXPR_MASQ_FLAGS },
    .{ "masq:reg_proto_min", libnftnl.NFTNL_EXPR_MASQ_REG_PROTO_MIN },
    .{ "masq:reg_proto_max", libnftnl.NFTNL_EXPR_MASQ_REG_PROTO_MAX },

    // Redirect expression
    .{ "redir:reg_proto_min", libnftnl.NFTNL_EXPR_REDIR_REG_PROTO_MIN },
    .{ "redir:reg_proto_max", libnftnl.NFTNL_EXPR_REDIR_REG_PROTO_MAX },
    .{ "redir:flags", libnftnl.NFTNL_EXPR_REDIR_FLAGS },
});

fn mapExprAttr(expr_type: []const u8, attr_name: []const u8) ?u16 {
    // Build composite key "expr_type:attr_name"
    var key_buf: [128]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}:{s}", .{ expr_type, attr_name }) catch {
        // If key too long, return null
        return null;
    };

    // Try expression-specific lookup first
    if (expr_attr_map.get(key)) |value| {
        return value;
    }

    // Fall back to generic attribute (no expr_type prefix)
    const generic_key = std.fmt.bufPrint(&key_buf, ":{s}", .{attr_name}) catch {
        return null;
    };

    return expr_attr_map.get(generic_key);
}

pub fn handleExprAlloc(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [expr_name]
    if (request.args.items.len != 1) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_alloc: expected 1 arg (expression name)"));
    }

    const expr_name = request.args.items[0].asBinary() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_alloc: invalid expression name"));
    };

    // Need null-terminated string for C
    const expr_name_z = try allocator.dupeZ(u8, expr_name);
    defer allocator.free(expr_name_z);

    const expr = libnftnl.exprAlloc(expr_name_z) catch |err| {
        const error_msg = try std.fmt.allocPrint(allocator, "expr_alloc_failed: {}", .{err});
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    const resource_id = try resource_mgr.allocateExpr(expr, expr_name);
    return common.okValueResponse(allocator, request.req_id, resource_id);
}

pub fn handleExprFree(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id]
    if (request.args.items.len != 1) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_free: expected 1 arg"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_free: invalid resource_id"));
    };

    // Get the resource
    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_free: resource not found"));
    };

    // Verify it's an expr resource
    if (resource.type != .expr) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_free: not an expr resource"));
    }

    // Free the expression and remove from resource manager
    resource_mgr.free(resource_id) catch {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_free: failed to free resource"));
    };

    return common.okResponse(allocator, request.req_id);
}

pub fn handleExprSetU8(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id, attr_atom, value_u8]
    if (request.args.items.len != 3) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u8: expected 3 args"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u8: invalid resource_id"));
    };

    const attr_name = request.args.items[1].asAtom() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u8: invalid attr"));
    };

    const value = request.args.items[2].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u8: invalid value"));
    };

    if (value > 255) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u8: value exceeds u8 range"));
    }

    // Get the resource
    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u8: resource not found"));
    };

    if (resource.type != .expr) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u8: not an expr resource"));
    }

    // Map attribute name to libnftnl constant based on expression type
    const expr_type = resource.expr_type_name orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u8: expression type not tracked"));
    };

    const attr_id = mapExprAttr(expr_type, attr_name) orelse {
        const error_msg = try std.fmt.allocPrint(allocator, "expr_set_u8: unknown attribute '{s}' for expression type '{s}'", .{ attr_name, expr_type });
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    libnftnl.exprSetU8(resource.ptr, attr_id, @intCast(value));

    return common.okResponse(allocator, request.req_id);
}

pub fn handleExprSetU16(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id, attr_atom, value_u16]
    if (request.args.items.len != 3) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u16: expected 3 args"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u16: invalid resource_id"));
    };

    const attr_name = request.args.items[1].asAtom() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u16: invalid attr"));
    };

    const value = request.args.items[2].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u16: invalid value"));
    };

    if (value > 65535) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u16: value exceeds u16 range"));
    }

    // Get the resource
    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u16: resource not found"));
    };

    if (resource.type != .expr) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u16: not an expr resource"));
    }

    const expr_type = resource.expr_type_name orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u16: expression type not tracked"));
    };

    const attr_id = mapExprAttr(expr_type, attr_name) orelse {
        const error_msg = try std.fmt.allocPrint(allocator, "expr_set_u16: unknown attribute '{s}' for expression type '{s}'", .{ attr_name, expr_type });
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    libnftnl.exprSetU16(resource.ptr, attr_id, @intCast(value));

    return common.okResponse(allocator, request.req_id);
}

pub fn handleExprSetU32(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id, attr_atom, value_u32]
    if (request.args.items.len != 3) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u32: expected 3 args"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u32: invalid resource_id"));
    };

    const attr_name = request.args.items[1].asAtom() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u32: invalid attr"));
    };

    const value = request.args.items[2].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u32: invalid value"));
    };

    // Get the resource
    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u32: resource not found"));
    };

    if (resource.type != .expr) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u32: not an expr resource"));
    }

    const expr_type = resource.expr_type_name orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u32: expression type not tracked"));
    };

    const attr_id = mapExprAttr(expr_type, attr_name) orelse {
        const error_msg = try std.fmt.allocPrint(allocator, "expr_set_u32: unknown attribute '{s}' for expression type '{s}'", .{ attr_name, expr_type });
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    libnftnl.exprSetU32(resource.ptr, attr_id, @intCast(value));

    return common.okResponse(allocator, request.req_id);
}

pub fn handleExprSetU64(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id, attr_atom, value_u64]
    if (request.args.items.len != 3) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u64: expected 3 args"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u64: invalid resource_id"));
    };

    const attr_name = request.args.items[1].asAtom() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u64: invalid attr"));
    };

    const value = request.args.items[2].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u64: invalid value"));
    };

    // Get the resource
    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u64: resource not found"));
    };

    if (resource.type != .expr) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u64: not an expr resource"));
    }

    const expr_type = resource.expr_type_name orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_u64: expression type not tracked"));
    };

    const attr_id = mapExprAttr(expr_type, attr_name) orelse {
        const error_msg = try std.fmt.allocPrint(allocator, "expr_set_u64: unknown attribute '{s}' for expression type '{s}'", .{ attr_name, expr_type });
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    libnftnl.exprSetU64(resource.ptr, attr_id, value);

    return common.okResponse(allocator, request.req_id);
}

pub fn handleExprSetStr(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id, attr_atom, value_string]
    if (request.args.items.len != 3) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_str: expected 3 args"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_str: invalid resource_id"));
    };

    const attr_name = request.args.items[1].asAtom() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_str: invalid attr"));
    };

    const value = request.args.items[2].asBinary() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_str: invalid value"));
    };

    // Get the resource
    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_str: resource not found"));
    };

    if (resource.type != .expr) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_str: not an expr resource"));
    }

    const expr_type = resource.expr_type_name orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_str: expression type not tracked"));
    };

    const attr_id = mapExprAttr(expr_type, attr_name) orelse {
        const error_msg = try std.fmt.allocPrint(allocator, "expr_set_str: unknown attribute '{s}' for expression type '{s}'", .{ attr_name, expr_type });
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    // Need null-terminated string for C
    const value_z = try allocator.dupeZ(u8, value);
    defer allocator.free(value_z);

    libnftnl.exprSetStr(resource.ptr, attr_id, value_z);

    return common.okResponse(allocator, request.req_id);
}

pub fn handleExprSetData(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id, attr_atom, binary_data]
    if (request.args.items.len != 3) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_data: expected 3 args"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_data: invalid resource_id"));
    };

    const attr_name = request.args.items[1].asAtom() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_data: invalid attr"));
    };

    const data = request.args.items[2].asBinary() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_data: invalid data"));
    };

    // Get the resource
    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_data: resource not found"));
    };

    if (resource.type != .expr) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_data: not an expr resource"));
    }

    const expr_type = resource.expr_type_name orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "expr_set_data: expression type not tracked"));
    };

    const attr_id = mapExprAttr(expr_type, attr_name) orelse {
        const error_msg = try std.fmt.allocPrint(allocator, "expr_set_data: unknown attribute '{s}' for expression type '{s}'", .{ attr_name, expr_type });
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    libnftnl.exprSet(resource.ptr, attr_id, data.ptr, @intCast(data.len));

    return common.okResponse(allocator, request.req_id);
}

// Set operations

