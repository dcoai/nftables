const std = @import("std");
const protocol = @import("../protocol.zig");
const resources = @import("../resources.zig");
const libnftnl = @import("../libnftnl.zig");
const netlink_errors = @import("../netlink_errors.zig");
const common = @import("common.zig");

/// Generic query configuration for listing resources
pub const QueryConfig = struct {
    msg_type_get: u16, // e.g., NFT_MSG_GETTABLE
    alloc_fn: *const fn () error{AllocationFailed}!*anyopaque,
    free_fn: *const fn (*anyopaque) void,
    parse_fn: *const fn (*const anyopaque, *anyopaque) c_int,
    serialize_fn: *const fn (std.mem.Allocator, *anyopaque) error{OutOfMemory}![]const u8,
    function_name: []const u8,
};

/// Generic list/dump handler
pub fn handleList(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    config: QueryConfig,
) !protocol.Response {
    // Validate args: [family]
    if (request.args.items.len != 1) {
        return common.errorResponse(
            allocator,
            request.req_id,
            try std.fmt.allocPrint(allocator, "{s}: expected 1 arg (family)", .{config.function_name}),
        );
    }

    const family = request.args.items[0].asU64() orelse {
        return common.errorResponse(
            allocator,
            request.req_id,
            try std.fmt.allocPrint(allocator, "{s}: invalid family", .{config.function_name}),
        );
    };

    // Build dump request
    var batch_buf_aligned: [512]u32 align(4) = undefined;
    const batch_buf: [*]u8 = @ptrCast(&batch_buf_aligned);

    const seq: u32 = 1;
    const flags: u16 = libnftnl.NLM_F_REQUEST | libnftnl.NLM_F_DUMP;

    const nlh = libnftnl.nlmsgBuildHdr(batch_buf, config.msg_type_get, @intCast(family), flags, seq);
    const msg_len = @as(*align(1) u32, @ptrCast(nlh)).*;

    // Open socket
    const nl_socket = libnftnl.nlSocketOpen(libnftnl.NETLINK_NETFILTER) orelse {
        return common.errorResponse(
            allocator,
            request.req_id,
            try std.fmt.allocPrint(allocator, "{s}: failed to open socket", .{config.function_name}),
        );
    };
    defer libnftnl.nlSocketClose(nl_socket);

    if (libnftnl.nlSocketBind(nl_socket, 0, 0) < 0) {
        return common.errorResponse(
            allocator,
            request.req_id,
            try std.fmt.allocPrint(allocator, "{s}: failed to bind socket", .{config.function_name}),
        );
    }

    // Send request
    if (libnftnl.nlSocketSend(nl_socket, batch_buf, msg_len) < 0) {
        return common.errorResponse(
            allocator,
            request.req_id,
            try std.fmt.allocPrint(allocator, "{s}: send failed", .{config.function_name}),
        );
    }

    // Receive and parse multiple responses
    var items: std.ArrayList([]const u8) = .empty;
    defer {
        for (items.items) |item| {
            allocator.free(item);
        }
        items.deinit(allocator);
    }

    const recv_buf = try allocator.alloc(u8, 8192);
    defer allocator.free(recv_buf);

    var done = false;
    while (!done) {
        const received = libnftnl.nlSocketRecvfrom(nl_socket, recv_buf.ptr, recv_buf.len);
        if (received <= 0) break;

        const response_data = recv_buf[0..@intCast(received)];

        // Check for errors
        if (netlink_errors.isError(response_data)) {
            const err_code = netlink_errors.parseError(response_data) orelse {
                return common.errorResponse(
                    allocator,
                    request.req_id,
                    try std.fmt.allocPrint(allocator, "{s}: parse error failed", .{config.function_name}),
                );
            };
            if (err_code != 0) {
                const err_msg = try netlink_errors.errnoToString(allocator, err_code);
                return common.errorResponse(allocator, request.req_id, err_msg);
            }
            continue; // Success ACK, continue
        }

        // Parse each message in the response buffer
        var offset: usize = 0;
        while (offset < response_data.len) {
            // Check if we have enough data for a header
            if (response_data.len - offset < 16) break; // nlmsghdr is 16 bytes

            const msg_ptr = response_data[offset..].ptr;
            const nlh_len_ptr: *align(1) const u32 = @ptrCast(msg_ptr);
            const nlh_len = nlh_len_ptr.*;

            // Check message type using our helper
            const msg_type = libnftnl.nlmsgGetType(msg_ptr);

            // Check for NLMSG_DONE
            if (msg_type == libnftnl.NLMSG_DONE) {
                done = true;
                break;
            }

            // Allocate and parse object
            const obj = try config.alloc_fn();
            defer config.free_fn(obj);

            const parse_result = config.parse_fn(msg_ptr, obj);
            if (parse_result < 0) {
                // Parse failed, skip this message
                offset += libnftnl.nlmsgAlign(nlh_len);
                continue;
            }

            // Serialize to binary for Elixir
            const serialized = try config.serialize_fn(allocator, obj);
            errdefer allocator.free(serialized);
            try items.append(allocator, serialized);

            // Move to next message
            offset += libnftnl.nlmsgAlign(nlh_len);
        }
    }

    // Return list of serialized items
    return protocol.Response{
        .allocator = allocator,
        .req_id = request.req_id,
        .payload = .{ .ok_list = try items.toOwnedSlice(allocator) },
    };
}

/// Serialize a table to a simple binary format for Elixir
/// Format: "name\0family\0flags\0"
fn serializeTable(allocator: std.mem.Allocator, table: *anyopaque) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Get table name
    const name = libnftnl.tableGetStr(table, libnftnl.NFTNL_TABLE_NAME);
    if (name) |n| {
        const name_slice = std.mem.span(n);
        try buf.appendSlice(allocator, name_slice);
    }
    try buf.append(allocator, 0);

    // Get family
    const family = libnftnl.tableGetU32(table, libnftnl.NFTNL_TABLE_FAMILY);
    const family_str = try std.fmt.allocPrint(allocator, "{d}", .{family});
    defer allocator.free(family_str);
    try buf.appendSlice(allocator, family_str);
    try buf.append(allocator, 0);

    // Get flags
    const flags = libnftnl.tableGetU32(table, libnftnl.NFTNL_TABLE_FLAGS);
    const flags_str = try std.fmt.allocPrint(allocator, "{d}", .{flags});
    defer allocator.free(flags_str);
    try buf.appendSlice(allocator, flags_str);
    try buf.append(allocator, 0);

    return try buf.toOwnedSlice(allocator);
}

/// Handle table list query
pub fn handleTableList(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    _ = resource_mgr; // Not needed for queries

    return handleList(allocator, request, .{
        .msg_type_get = libnftnl.NFT_MSG_GETTABLE,
        .alloc_fn = libnftnl.tableAlloc,
        .free_fn = libnftnl.tableFree,
        .parse_fn = libnftnl.tableNlmsgParse,
        .serialize_fn = serializeTable,
        .function_name = "table_list",
    });
}

/// Serialize a chain to a simple binary format for Elixir
/// Format: "name\0table\0type\0hook\0prio\0policy\0family\0"
fn serializeChain(allocator: std.mem.Allocator, chain: *anyopaque) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Get chain name
    const name = libnftnl.chainGetStr(chain, libnftnl.NFTNL_CHAIN_NAME);
    if (name) |n| {
        const name_slice = std.mem.span(n);
        try buf.appendSlice(allocator, name_slice);
    }
    try buf.append(allocator, 0);

    // Get table name
    const table = libnftnl.chainGetStr(chain, libnftnl.NFTNL_CHAIN_TABLE);
    if (table) |t| {
        const table_slice = std.mem.span(t);
        try buf.appendSlice(allocator, table_slice);
    }
    try buf.append(allocator, 0);

    // Get type (may be null for base chains)
    const chain_type = libnftnl.chainGetStr(chain, libnftnl.NFTNL_CHAIN_TYPE);
    if (chain_type) |t| {
        const type_slice = std.mem.span(t);
        try buf.appendSlice(allocator, type_slice);
    }
    try buf.append(allocator, 0);

    // Get hook (for base chains)
    const hook = libnftnl.chainGetU32(chain, libnftnl.NFTNL_CHAIN_HOOKNUM);
    const hook_str = try std.fmt.allocPrint(allocator, "{d}", .{hook});
    defer allocator.free(hook_str);
    try buf.appendSlice(allocator, hook_str);
    try buf.append(allocator, 0);

    // Get priority
    const prio = libnftnl.chainGetU32(chain, libnftnl.NFTNL_CHAIN_PRIO);
    const prio_str = try std.fmt.allocPrint(allocator, "{d}", .{prio});
    defer allocator.free(prio_str);
    try buf.appendSlice(allocator, prio_str);
    try buf.append(allocator, 0);

    // Get policy
    const policy = libnftnl.chainGetU32(chain, libnftnl.NFTNL_CHAIN_POLICY);
    const policy_str = try std.fmt.allocPrint(allocator, "{d}", .{policy});
    defer allocator.free(policy_str);
    try buf.appendSlice(allocator, policy_str);
    try buf.append(allocator, 0);

    // Get family
    const family = libnftnl.chainGetU32(chain, libnftnl.NFTNL_CHAIN_FAMILY);
    const family_str = try std.fmt.allocPrint(allocator, "{d}", .{family});
    defer allocator.free(family_str);
    try buf.appendSlice(allocator, family_str);
    try buf.append(allocator, 0);

    return try buf.toOwnedSlice(allocator);
}

/// Handle chain list query
pub fn handleChainList(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    _ = resource_mgr; // Not needed for queries

    return handleList(allocator, request, .{
        .msg_type_get = libnftnl.NFT_MSG_GETCHAIN,
        .alloc_fn = libnftnl.chainAlloc,
        .free_fn = libnftnl.chainFree,
        .parse_fn = libnftnl.chainNlmsgParse,
        .serialize_fn = serializeChain,
        .function_name = "chain_list",
    });
}

/// Serialize a rule to a simple binary format for Elixir
/// Format: "table\0chain\0family\0handle\0position\0"
fn serializeRule(allocator: std.mem.Allocator, rule: *anyopaque) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Get table name
    const table = libnftnl.ruleGetStr(rule, libnftnl.NFTNL_RULE_TABLE);
    if (table) |t| {
        const table_slice = std.mem.span(t);
        try buf.appendSlice(allocator, table_slice);
    }
    try buf.append(allocator, 0);

    // Get chain name
    const chain = libnftnl.ruleGetStr(rule, libnftnl.NFTNL_RULE_CHAIN);
    if (chain) |c| {
        const chain_slice = std.mem.span(c);
        try buf.appendSlice(allocator, chain_slice);
    }
    try buf.append(allocator, 0);

    // Get family
    const family = libnftnl.ruleGetU32(rule, libnftnl.NFTNL_RULE_FAMILY);
    const family_str = try std.fmt.allocPrint(allocator, "{d}", .{family});
    defer allocator.free(family_str);
    try buf.appendSlice(allocator, family_str);
    try buf.append(allocator, 0);

    // Get handle
    const handle = libnftnl.ruleGetU64(rule, libnftnl.NFTNL_RULE_HANDLE);
    const handle_str = try std.fmt.allocPrint(allocator, "{d}", .{handle});
    defer allocator.free(handle_str);
    try buf.appendSlice(allocator, handle_str);
    try buf.append(allocator, 0);

    // Get position
    const position = libnftnl.ruleGetU64(rule, libnftnl.NFTNL_RULE_POSITION);
    const position_str = try std.fmt.allocPrint(allocator, "{d}", .{position});
    defer allocator.free(position_str);
    try buf.appendSlice(allocator, position_str);
    try buf.append(allocator, 0);

    return try buf.toOwnedSlice(allocator);
}

/// Handle rule list query
pub fn handleRuleList(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    _ = resource_mgr; // Not needed for queries

    return handleList(allocator, request, .{
        .msg_type_get = libnftnl.NFT_MSG_GETRULE,
        .alloc_fn = libnftnl.ruleAlloc,
        .free_fn = libnftnl.ruleFree,
        .parse_fn = libnftnl.ruleNlmsgParse,
        .serialize_fn = serializeRule,
        .function_name = "rule_list",
    });
}

/// Serialize a set to a simple binary format for Elixir
/// Format: "name\0table\0family\0key_type\0key_len\0flags\0"
fn serializeSet(allocator: std.mem.Allocator, set: *anyopaque) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Get set name
    const name = libnftnl.setGetStr(set, libnftnl.NFTNL_SET_NAME);
    if (name) |n| {
        const name_slice = std.mem.span(n);
        try buf.appendSlice(allocator, name_slice);
    }
    try buf.append(allocator, 0);

    // Get table name
    const table = libnftnl.setGetStr(set, libnftnl.NFTNL_SET_TABLE);
    if (table) |t| {
        const table_slice = std.mem.span(t);
        try buf.appendSlice(allocator, table_slice);
    }
    try buf.append(allocator, 0);

    // Get family
    const family = libnftnl.setGetU32(set, libnftnl.NFTNL_SET_FAMILY);
    const family_str = try std.fmt.allocPrint(allocator, "{d}", .{family});
    defer allocator.free(family_str);
    try buf.appendSlice(allocator, family_str);
    try buf.append(allocator, 0);

    // Get key_type
    const key_type = libnftnl.setGetU32(set, libnftnl.NFTNL_SET_KEY_TYPE);
    const key_type_str = try std.fmt.allocPrint(allocator, "{d}", .{key_type});
    defer allocator.free(key_type_str);
    try buf.appendSlice(allocator, key_type_str);
    try buf.append(allocator, 0);

    // Get key_len
    const key_len = libnftnl.setGetU32(set, libnftnl.NFTNL_SET_KEY_LEN);
    const key_len_str = try std.fmt.allocPrint(allocator, "{d}", .{key_len});
    defer allocator.free(key_len_str);
    try buf.appendSlice(allocator, key_len_str);
    try buf.append(allocator, 0);

    // Get flags
    const flags = libnftnl.setGetU32(set, libnftnl.NFTNL_SET_FLAGS);
    const flags_str = try std.fmt.allocPrint(allocator, "{d}", .{flags});
    defer allocator.free(flags_str);
    try buf.appendSlice(allocator, flags_str);
    try buf.append(allocator, 0);

    return try buf.toOwnedSlice(allocator);
}

/// Handle set list query
pub fn handleSetList(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    _ = resource_mgr; // Not needed for queries

    return handleList(allocator, request, .{
        .msg_type_get = libnftnl.NFT_MSG_GETSET,
        .alloc_fn = libnftnl.setAlloc,
        .free_fn = libnftnl.setFree,
        .parse_fn = libnftnl.setNlmsgParse,
        .serialize_fn = serializeSet,
        .function_name = "set_list",
    });
}

/// Serialize a set element to binary format
/// Format: "key_data\0flags\0"
/// For binary key data, we encode as hex string
fn serializeSetElem(allocator: std.mem.Allocator, elem: *anyopaque) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Get key data (binary)
    var key_len: u32 = 0;
    const key_data = libnftnl.setElemGet(elem, libnftnl.NFTNL_SET_ELEM_KEY, &key_len);

    if (key_data) |data| {
        // Convert binary key to hex string for readability
        const data_bytes: [*]const u8 = @ptrCast(data);
        const hex_chars = "0123456789abcdef";

        for (0..key_len) |i| {
            const byte = data_bytes[i];
            try buf.append(allocator, hex_chars[byte >> 4]);
            try buf.append(allocator, hex_chars[byte & 0x0F]);
        }
    } else {
        try buf.appendSlice(allocator, "no_key");
    }
    try buf.append(allocator, 0);

    // Get flags (may not be set for all elements)
    const flags = if (libnftnl.setElemIsSet(elem, libnftnl.NFTNL_SET_ELEM_FLAGS))
        libnftnl.setElemGetU32(elem, libnftnl.NFTNL_SET_ELEM_FLAGS)
    else
        0;
    const flags_str = try std.fmt.allocPrint(allocator, "{d}", .{flags});
    defer allocator.free(flags_str);
    try buf.appendSlice(allocator, flags_str);
    try buf.append(allocator, 0);

    return try buf.toOwnedSlice(allocator);
}

/// Handle set element list query
/// Arguments: [family, table_name, set_name]
pub fn handleSetElemList(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    _ = resource_mgr; // Not needed for queries

    // Expected args: [family, table_name, set_name]
    if (request.args.items.len != 3) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_list: expected 3 args (family, table_name, set_name)"));
    }

    const family = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_list: invalid family"));
    };

    const table_name = request.args.items[1].asBinary() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_list: invalid table_name"));
    };

    const set_name = request.args.items[2].asBinary() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_list: invalid set_name"));
    };

    // Create a set object and set its attributes for the query
    const set = libnftnl.setAlloc() catch {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_list: failed to allocate set"));
    };
    defer libnftnl.setFree(set);

    // Set table name, set name, and family on the set
    libnftnl.setSetStr(set, libnftnl.NFTNL_SET_TABLE, @ptrCast(table_name.ptr));
    libnftnl.setSetStr(set, libnftnl.NFTNL_SET_NAME, @ptrCast(set_name.ptr));
    libnftnl.setSetU32(set, libnftnl.NFTNL_SET_FAMILY, @intCast(family));

    // Open netlink socket
    const nl_socket = libnftnl.nlSocketOpen(libnftnl.NETLINK_NETFILTER) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_list: failed to open netlink socket"));
    };
    defer libnftnl.nlSocketClose(nl_socket);

    if (libnftnl.nlSocketBind(nl_socket, 0, 0) < 0) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_list: failed to bind socket"));
    }

    // Build the netlink message
    var buf_aligned: [1024]u32 align(4) = undefined;
    const buf: [*]u8 = @ptrCast(&buf_aligned);
    const seq: u32 = 1;
    const flags: u16 = libnftnl.NLM_F_REQUEST | libnftnl.NLM_F_DUMP;

    const nlh = libnftnl.nlmsgBuildHdr(
        buf,
        libnftnl.NFT_MSG_GETSETELEM,
        @intCast(family),
        flags,
        seq,
    );

    // Build payload with set attributes
    libnftnl.setElemsNlmsgBuildPayload(nlh, set);

    // Send the request
    const msg_len = @as(*align(1) u32, @ptrCast(nlh)).*;
    if (libnftnl.nlSocketSend(nl_socket, buf, msg_len) < 0) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_list: failed to send request"));
    }

    // Receive responses and collect elements
    var items: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (items.items) |item| {
            allocator.free(item);
        }
        items.deinit(allocator);
    }

    // Use properly aligned buffer for netlink messages (aligned to u32)
    var recv_buf_aligned: [4096]u32 align(4) = undefined;
    const recv_buf: [*]u8 = @ptrCast(&recv_buf_aligned);
    const recv_buf_len = @sizeOf(@TypeOf(recv_buf_aligned));
    var done = false;

    while (!done) {
        const received = libnftnl.nlSocketRecvfrom(nl_socket, recv_buf, recv_buf_len);
        if (received <= 0) {
            break;
        }

        const response_data = recv_buf[0..@intCast(received)];
        var offset: usize = 0;

        while (offset < response_data.len) {
            // Check if we have enough data for a header
            if (response_data.len - offset < 16) break; // nlmsghdr is 16 bytes

            const msg_ptr = response_data[offset..].ptr;
            const nlh_len_ptr: *align(1) const u32 = @ptrCast(msg_ptr);
            const nlh_len = nlh_len_ptr.*;

            const msg_type = libnftnl.nlmsgGetType(msg_ptr);

            if (msg_type == libnftnl.NLMSG_DONE) {
                done = true;
                break;
            }

            // Parse elements into the set object
            // We need to cast to properly aligned pointer for libnftnl
            _ = libnftnl.setElemsNlmsgParse(@ptrCast(@alignCast(msg_ptr)), set);

            // Advance to next message
            offset += libnftnl.nlmsgAlign(nlh_len);
        }
    }

    // Now iterate through the elements in the set and serialize each one
    const iter = libnftnl.setElemsIterCreate(set) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_list: failed to create iterator"));
    };
    defer libnftnl.setElemsIterDestroy(iter);

    // Iterate through all elements
    // Note: Call iterNext() first to get the first element (standard libnftnl pattern)
    var current_elem = libnftnl.setElemsIterNext(iter);
    while (current_elem != null) {
        const serialized = try serializeSetElem(allocator, current_elem.?);
        try items.append(allocator, serialized);

        current_elem = libnftnl.setElemsIterNext(iter);
    }

    return protocol.Response{
        .allocator = allocator,
        .req_id = request.req_id,
        .payload = .{ .ok_list = try items.toOwnedSlice(allocator) },
    };
}
