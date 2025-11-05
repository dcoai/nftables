const std = @import("std");
const protocol = @import("../protocol.zig");
const resources = @import("../resources.zig");
const libnftnl = @import("../libnftnl.zig");
const netlink_errors = @import("../netlink_errors.zig");

/// Response helper functions to reduce duplication

pub fn errorResponse(allocator: std.mem.Allocator, req_id: u64, msg: []const u8) protocol.Response {
    return protocol.Response{
        .allocator = allocator,
        .req_id = req_id,
        .payload = .{ .error_msg = msg },
    };
}

pub fn errorErrnoResponse(allocator: std.mem.Allocator, req_id: u64, errno: c_int) protocol.Response {
    return protocol.Response{
        .allocator = allocator,
        .req_id = req_id,
        .payload = .{ .error_errno = errno },
    };
}

pub fn okResponse(allocator: std.mem.Allocator, req_id: u64) protocol.Response {
    return protocol.Response{
        .allocator = allocator,
        .req_id = req_id,
        .payload = .{ .ok = {} },
    };
}

pub fn okValueResponse(allocator: std.mem.Allocator, req_id: u64, value: u64) protocol.Response {
    return protocol.Response{
        .allocator = allocator,
        .req_id = req_id,
        .payload = .{ .ok_value = value },
    };
}

pub fn okStringResponse(allocator: std.mem.Allocator, req_id: u64, value: []const u8) protocol.Response {
    return protocol.Response{
        .allocator = allocator,
        .req_id = req_id,
        .payload = .{ .ok_string = value },
    };
}

/// Validation helper functions

/// Validate the number of arguments in a request
pub fn validateArgCount(
    request: protocol.Request,
    expected_count: usize,
) !void {
    if (request.args.items.len != expected_count) {
        return error.InvalidArgCount;
    }
}

/// Extract resource ID from request arguments
pub fn extractResourceId(
    request: protocol.Request,
    arg_index: usize,
) ?u64 {
    return request.args.items[arg_index].asU64();
}

/// Extract atom (string) value from request arguments
pub fn extractAtom(
    request: protocol.Request,
    arg_index: usize,
) ?[]const u8 {
    return request.args.items[arg_index].asAtom();
}

/// Extract binary (string) value from request arguments
pub fn extractBinary(
    request: protocol.Request,
    arg_index: usize,
) ?[]const u8 {
    return request.args.items[arg_index].asBinary();
}

/// Extract u64 value from request arguments
pub fn extractU64(
    request: protocol.Request,
    arg_index: usize,
) ?u64 {
    return request.args.items[arg_index].asU64();
}

/// Validate u8 range
pub fn validateU8Range(value: u64) !u8 {
    if (value > 255) {
        return error.ValueOutOfRange;
    }
    return @intCast(value);
}

/// Validate u16 range
pub fn validateU16Range(value: u64) !u16 {
    if (value > 65535) {
        return error.ValueOutOfRange;
    }
    return @intCast(value);
}

/// Resource management helpers

/// Get resource and validate its type
pub fn getAndValidateResource(
    resource_mgr: *resources.ResourceManager,
    resource_id: u64,
    expected_type: resources.ResourceType,
) !resources.Resource {
    const resource = resource_mgr.get(resource_id) orelse {
        return error.ResourceNotFound;
    };

    if (resource.type != expected_type) {
        return error.WrongResourceType;
    }

    return resource;
}

/// Configuration for generic send_to_kernel operations
pub const SendToKernelConfig = struct {
    resource_type: resources.ResourceType,
    msg_type_new: u16,
    msg_type_del: u16,
    family_attr: u16,
    get_family_fn: *const fn (*anyopaque, u16) u32,
    build_payload_fn: *const fn (*anyopaque, *anyopaque) void,
    function_name: []const u8,
};

/// Generic send_to_kernel handler that works for any resource type
pub fn handleSendToKernel(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
    config: SendToKernelConfig,
) !protocol.Response {
    // Validate args
    validateArgCount(request, 2) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: expected 2 args", .{config.function_name}));
    };

    const resource_id = extractResourceId(request, 0) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource_id", .{config.function_name}));
    };

    const cmd = extractAtom(request, 1) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid cmd", .{config.function_name}));
    };

    // Get resource
    const resource = getAndValidateResource(resource_mgr, resource_id, config.resource_type) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource", .{config.function_name}));
    };

    // Determine message type
    const msg_type: u16 = if (std.mem.eql(u8, cmd, "add"))
        config.msg_type_new
    else if (std.mem.eql(u8, cmd, "delete"))
        config.msg_type_del
    else {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: cmd must be 'add' or 'delete'", .{config.function_name}));
    };

    // Get family
    const family_u32 = config.get_family_fn(resource.ptr, config.family_attr);
    const family: u16 = @intCast(family_u32);

    // Create batch buffer (4-byte aligned for netlink)
    var batch_buf_aligned: [2048]u32 align(4) = undefined;
    const batch_buf: [*]u8 = @ptrCast(&batch_buf_aligned);
    const batch_buf_len: usize = 2048 * 4; // 8192 bytes

    // Initialize mnl batch
    const batch = libnftnl.mnlBatchStart(batch_buf, batch_buf_len);
    defer libnftnl.mnlBatchStop(batch);

    var seq: u32 = 1;

    // Build batch begin message
    _ = libnftnl.batchBegin(libnftnl.mnlBatchCurrent(batch), seq);
    _ = libnftnl.mnlBatchNext(batch);
    seq += 1;

    // Build resource message
    // Rules need NLM_F_APPEND to append to the chain
    // Other resources (sets, tables, chains) only need NLM_F_CREATE
    const flags: u16 = libnftnl.NLM_F_REQUEST | libnftnl.NLM_F_ACK |
        if (std.mem.eql(u8, cmd, "add")) blk: {
            const create_flag = libnftnl.NLM_F_CREATE;
            // Only rules need NLM_F_APPEND
            const append_flag = if (config.resource_type == .rule) libnftnl.NLM_F_APPEND else 0;
            break :blk create_flag | append_flag;
        } else 0;

    const nlh = libnftnl.nlmsgBuildHdr(libnftnl.mnlBatchCurrent(batch), msg_type, family, flags, seq);
    config.build_payload_fn(nlh, resource.ptr);
    _ = libnftnl.mnlBatchNext(batch);
    seq += 1;

    // Build batch end message
    _ = libnftnl.batchEnd(libnftnl.mnlBatchCurrent(batch), seq);
    _ = libnftnl.mnlBatchNext(batch);

    // Get batch data
    const buf = libnftnl.mnlBatchHead(batch);
    const buf_len = libnftnl.mnlBatchSize(batch);

    // Open netlink socket
    const nl_socket = libnftnl.nlSocketOpen(libnftnl.NETLINK_NETFILTER) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: failed to open netlink socket", .{config.function_name}));
    };
    defer libnftnl.nlSocketClose(nl_socket);

    // Bind socket
    if (libnftnl.nlSocketBind(nl_socket, 0, 0) < 0) {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: failed to bind netlink socket", .{config.function_name}));
    }

    // Send buffer
    const bytes_sent = libnftnl.nlSocketSend(nl_socket, buf, buf_len);
    if (bytes_sent < 0) {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: send failed with error code {d}", .{ config.function_name, bytes_sent }));
    }

    // Receive response
    const recv_buf = try allocator.alloc(u8, 8192);
    defer allocator.free(recv_buf);

    const received = libnftnl.nlSocketRecvfrom(nl_socket, recv_buf.ptr, recv_buf.len);
    if (received < 0) {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: failed to receive response", .{config.function_name}));
    }

    // Parse errors
    const response_data = recv_buf[0..@intCast(received)];

    if (netlink_errors.isError(response_data)) {
        const err_code = netlink_errors.parseError(response_data) orelse {
            return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: failed to parse error", .{config.function_name}));
        };

        if (err_code != 0) {
            return errorErrnoResponse(allocator, request.req_id, err_code);
        }
    }

    return okResponse(allocator, request.req_id);
}

/// Generic setter/getter configuration

/// Configuration for generic setStr operations
pub const SetStrConfig = struct {
    resource_type: resources.ResourceType,
    attr_map: *const std.StaticStringMap(u16),
    set_fn: *const fn (*anyopaque, u16, [*:0]const u8) void,
    function_name: []const u8,
};

/// Generic setStr handler
pub fn handleSetStr(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
    config: SetStrConfig,
) !protocol.Response {
    validateArgCount(request, 3) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: expected 3 args", .{config.function_name}));
    };

    const resource_id = extractResourceId(request, 0) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource_id", .{config.function_name}));
    };

    const attr_name = extractAtom(request, 1) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid attr", .{config.function_name}));
    };

    const value = extractBinary(request, 2) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid value", .{config.function_name}));
    };

    const resource = getAndValidateResource(resource_mgr, resource_id, config.resource_type) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource", .{config.function_name}));
    };

    const attr_const = config.attr_map.get(attr_name) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: unknown attr '{s}'", .{ config.function_name, attr_name }));
    };

    // Convert to null-terminated string for C
    const value_z = try allocator.dupeZ(u8, value);
    defer allocator.free(value_z);

    config.set_fn(resource.ptr, attr_const, value_z);

    return okResponse(allocator, request.req_id);
}

/// Configuration for generic setU32 operations
pub const SetU32Config = struct {
    resource_type: resources.ResourceType,
    attr_map: *const std.StaticStringMap(u16),
    set_fn: *const fn (*anyopaque, u16, u32) void,
    function_name: []const u8,
};

/// Generic setU32 handler
pub fn handleSetU32(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
    config: SetU32Config,
) !protocol.Response {
    validateArgCount(request, 3) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: expected 3 args", .{config.function_name}));
    };

    const resource_id = extractResourceId(request, 0) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource_id", .{config.function_name}));
    };

    const attr_name = extractAtom(request, 1) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid attr", .{config.function_name}));
    };

    const value = extractU64(request, 2) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid value", .{config.function_name}));
    };

    const resource = getAndValidateResource(resource_mgr, resource_id, config.resource_type) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource", .{config.function_name}));
    };

    const attr_const = config.attr_map.get(attr_name) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: unknown attr '{s}'", .{ config.function_name, attr_name }));
    };

    config.set_fn(resource.ptr, attr_const, @intCast(value));

    return okResponse(allocator, request.req_id);
}

/// Configuration for generic setU64 operations
pub const SetU64Config = struct {
    resource_type: resources.ResourceType,
    attr_map: *const std.StaticStringMap(u16),
    set_fn: *const fn (*anyopaque, u16, u64) void,
    function_name: []const u8,
};

/// Generic setU64 handler
pub fn handleSetU64(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
    config: SetU64Config,
) !protocol.Response {
    validateArgCount(request, 3) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: expected 3 args", .{config.function_name}));
    };

    const resource_id = extractResourceId(request, 0) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource_id", .{config.function_name}));
    };

    const attr_name = extractAtom(request, 1) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid attr", .{config.function_name}));
    };

    const value = extractU64(request, 2) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid value", .{config.function_name}));
    };

    const resource = getAndValidateResource(resource_mgr, resource_id, config.resource_type) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource", .{config.function_name}));
    };

    const attr_const = config.attr_map.get(attr_name) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: unknown attr '{s}'", .{ config.function_name, attr_name }));
    };

    config.set_fn(resource.ptr, attr_const, value);

    return okResponse(allocator, request.req_id);
}

/// Configuration for generic setU8 operations
pub const SetU8Config = struct {
    resource_type: resources.ResourceType,
    attr_map: *const std.StaticStringMap(u16),
    set_fn: *const fn (*anyopaque, u16, u8) void,
    function_name: []const u8,
};

/// Generic setU8 handler
pub fn handleSetU8(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
    config: SetU8Config,
) !protocol.Response {
    validateArgCount(request, 3) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: expected 3 args", .{config.function_name}));
    };

    const resource_id = extractResourceId(request, 0) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource_id", .{config.function_name}));
    };

    const attr_name = extractAtom(request, 1) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid attr", .{config.function_name}));
    };

    const value = extractU64(request, 2) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid value", .{config.function_name}));
    };

    const value_u8 = validateU8Range(value) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: value exceeds u8 range", .{config.function_name}));
    };

    const resource = getAndValidateResource(resource_mgr, resource_id, config.resource_type) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource", .{config.function_name}));
    };

    const attr_const = config.attr_map.get(attr_name) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: unknown attr '{s}'", .{ config.function_name, attr_name }));
    };

    config.set_fn(resource.ptr, attr_const, value_u8);

    return okResponse(allocator, request.req_id);
}

/// Configuration for generic getStr operations
pub const GetStrConfig = struct {
    resource_type: resources.ResourceType,
    attr_map: *const std.StaticStringMap(u16),
    get_fn: *const fn (*anyopaque, u16) ?[*:0]const u8,
    function_name: []const u8,
};

/// Generic getStr handler
pub fn handleGetStr(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
    config: GetStrConfig,
) !protocol.Response {
    validateArgCount(request, 2) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: expected 2 args", .{config.function_name}));
    };

    const resource_id = extractResourceId(request, 0) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource_id", .{config.function_name}));
    };

    const attr_name = extractAtom(request, 1) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid attr", .{config.function_name}));
    };

    const resource = getAndValidateResource(resource_mgr, resource_id, config.resource_type) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource", .{config.function_name}));
    };

    const attr_const = config.attr_map.get(attr_name) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: unknown attr '{s}'", .{ config.function_name, attr_name }));
    };

    const value_ptr = config.get_fn(resource.ptr, attr_const) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: attribute not set", .{config.function_name}));
    };

    // Convert C string to Zig slice
    const value_len = std.mem.len(value_ptr);
    const value = try allocator.dupe(u8, value_ptr[0..value_len]);

    return okStringResponse(allocator, request.req_id, value);
}

/// Configuration for generic getU32 operations
pub const GetU32Config = struct {
    resource_type: resources.ResourceType,
    attr_map: *const std.StaticStringMap(u16),
    get_fn: *const fn (*anyopaque, u16) u32,
    function_name: []const u8,
};

/// Generic getU32 handler
pub fn handleGetU32(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
    config: GetU32Config,
) !protocol.Response {
    validateArgCount(request, 2) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: expected 2 args", .{config.function_name}));
    };

    const resource_id = extractResourceId(request, 0) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource_id", .{config.function_name}));
    };

    const attr_name = extractAtom(request, 1) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid attr", .{config.function_name}));
    };

    const resource = getAndValidateResource(resource_mgr, resource_id, config.resource_type) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource", .{config.function_name}));
    };

    const attr_const = config.attr_map.get(attr_name) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: unknown attr '{s}'", .{ config.function_name, attr_name }));
    };

    const value = config.get_fn(resource.ptr, attr_const);

    return okValueResponse(allocator, request.req_id, value);
}

/// Configuration for generic getU64 operations
pub const GetU64Config = struct {
    resource_type: resources.ResourceType,
    attr_map: *const std.StaticStringMap(u16),
    get_fn: *const fn (*anyopaque, u16) u64,
    function_name: []const u8,
};

/// Generic getU64 handler
pub fn handleGetU64(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
    config: GetU64Config,
) !protocol.Response {
    validateArgCount(request, 2) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: expected 2 args", .{config.function_name}));
    };

    const resource_id = extractResourceId(request, 0) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource_id", .{config.function_name}));
    };

    const attr_name = extractAtom(request, 1) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid attr", .{config.function_name}));
    };

    const resource = getAndValidateResource(resource_mgr, resource_id, config.resource_type) catch {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: invalid resource", .{config.function_name}));
    };

    const attr_const = config.attr_map.get(attr_name) orelse {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "{s}: unknown attr '{s}'", .{ config.function_name, attr_name }));
    };

    const value = config.get_fn(resource.ptr, attr_const);

    return okValueResponse(allocator, request.req_id, value);
}
