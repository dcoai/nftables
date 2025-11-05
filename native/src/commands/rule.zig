const std = @import("std");
const protocol = @import("../protocol.zig");
const resources = @import("../resources.zig");
const libnftnl = @import("../libnftnl.zig");
const netlink_errors = @import("../netlink_errors.zig");
const common = @import("common.zig");

// Compile-time attribute maps for rule operations
const rule_attr_str_map = std.StaticStringMap(u16).initComptime(.{
    .{ "table", libnftnl.NFTNL_RULE_TABLE },
    .{ "chain", libnftnl.NFTNL_RULE_CHAIN },
});

const rule_attr_u32_map = std.StaticStringMap(u16).initComptime(.{
    .{ "family", libnftnl.NFTNL_RULE_FAMILY },
});

const rule_attr_u64_map = std.StaticStringMap(u16).initComptime(.{
    .{ "position", libnftnl.NFTNL_RULE_POSITION },
    .{ "handle", libnftnl.NFTNL_RULE_HANDLE },
});

pub fn handleRuleAlloc(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    const rule = libnftnl.ruleAlloc() catch |err| {
        const error_msg = try std.fmt.allocPrint(allocator, "rule_alloc_failed: {}", .{err});
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    const resource_id = try resource_mgr.allocate(.rule, rule);

    return common.okValueResponse(allocator, request.req_id, resource_id);
}

pub fn handleRuleFree(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id]
    if (request.args.items.len != 1) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_free: expected 1 arg"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_free: invalid resource_id"));
    };

    // Get the resource
    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_free: resource not found"));
    };

    if (resource.type != .rule) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_free: not a rule resource"));
    }

    // Free the resource (this calls ruleFree internally and removes from tracking)
    resource_mgr.free(resource_id) catch {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_free: failed to free resource"));
    };

    return common.okResponse(allocator, request.req_id);
}

pub fn handleRuleSetStr(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSetStr(allocator, request, resource_mgr, .{
        .resource_type = .rule,
        .attr_map = &rule_attr_str_map,
        .set_fn = libnftnl.ruleSetStr,
        .function_name = "rule_set_str",
    });
}

pub fn handleRuleSetU32(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSetU32(allocator, request, resource_mgr, .{
        .resource_type = .rule,
        .attr_map = &rule_attr_u32_map,
        .set_fn = libnftnl.ruleSetU32,
        .function_name = "rule_set_u32",
    });
}

pub fn handleRuleSetU64(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSetU64(allocator, request, resource_mgr, .{
        .resource_type = .rule,
        .attr_map = &rule_attr_u64_map,
        .set_fn = libnftnl.ruleSetU64,
        .function_name = "rule_set_u64",
    });
}

pub fn handleRuleGetStr(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleGetStr(allocator, request, resource_mgr, .{
        .resource_type = .rule,
        .attr_map = &rule_attr_str_map,
        .get_fn = libnftnl.ruleGetStr,
        .function_name = "rule_get_str",
    });
}

pub fn handleRuleGetU32(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleGetU32(allocator, request, resource_mgr, .{
        .resource_type = .rule,
        .attr_map = &rule_attr_u32_map,
        .get_fn = libnftnl.ruleGetU32,
        .function_name = "rule_get_u32",
    });
}

pub fn handleRuleGetU64(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleGetU64(allocator, request, resource_mgr, .{
        .resource_type = .rule,
        .attr_map = &rule_attr_u64_map,
        .get_fn = libnftnl.ruleGetU64,
        .function_name = "rule_get_u64",
    });
}

pub fn handleRuleAddExpr(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [rule_id, expr_id]
    if (request.args.items.len != 2) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_add_expr: expected 2 args"));
    }

    const rule_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_add_expr: invalid rule_id"));
    };

    const expr_id = request.args.items[1].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_add_expr: invalid expr_id"));
    };

    // Get the rule resource
    const rule_resource = resource_mgr.get(rule_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_add_expr: rule not found"));
    };

    if (rule_resource.type != .rule) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_add_expr: first arg not a rule resource"));
    }

    // Get the expression resource
    const expr_resource = resource_mgr.get(expr_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_add_expr: expr not found"));
    };

    if (expr_resource.type != .expr) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "rule_add_expr: second arg not an expr resource"));
    }

    // Add the expression to the rule (transfers ownership to the rule)
    libnftnl.ruleAddExpr(rule_resource.ptr, expr_resource.ptr);

    // Release the expression from our tracking since ownership was transferred to the rule.
    // The rule will free the expression when the rule itself is freed.
    resource_mgr.release(expr_id) catch |err| {
        const err_msg = try std.fmt.allocPrint(allocator, "rule_add_expr: failed to release expr resource: {}", .{err});
        return common.errorResponse(allocator, request.req_id, err_msg);
    };

    return common.okResponse(allocator, request.req_id);
}

// Expression operations

pub fn handleRuleSendToKernel(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    return common.handleSendToKernel(allocator, request, resource_mgr, .{
        .resource_type = .rule,
        .msg_type_new = libnftnl.NFT_MSG_NEWRULE,
        .msg_type_del = libnftnl.NFT_MSG_DELRULE,
        .family_attr = libnftnl.NFTNL_RULE_FAMILY,
        .get_family_fn = libnftnl.ruleGetU32,
        .build_payload_fn = libnftnl.ruleNlmsgBuildPayload,
        .function_name = "rule_send_to_kernel",
    });
}

