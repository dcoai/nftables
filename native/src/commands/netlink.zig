const std = @import("std");
const protocol = @import("../protocol.zig");
const resources = @import("../resources.zig");
const libnftnl = @import("../libnftnl.zig");
const netlink_errors = @import("../netlink_errors.zig");
const common = @import("common.zig");

pub fn handleNlSocketOpen(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [] (no args, always opens NETLINK_NETFILTER)
    if (request.args.items.len != 0) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_socket_open: expected 0 args"));
    }

    // Open netlink socket for NETLINK_NETFILTER
    const nl_socket = libnftnl.nlSocketOpen(libnftnl.NETLINK_NETFILTER) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_socket_open: failed to open netlink socket"));
    };

    // Bind the socket
    const bind_result = libnftnl.nlSocketBind(nl_socket, 0, 0);
    if (bind_result < 0) {
        libnftnl.nlSocketClose(nl_socket);
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_socket_open: failed to bind socket"));
    }

    // Register as resource
    const resource_id = try resource_mgr.allocate(.nl_socket, nl_socket);
    return common.okValueResponse(allocator, request.req_id, resource_id);
}

pub fn handleNlSocketClose(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [socket_id]
    if (request.args.items.len != 1) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_socket_close: expected 1 arg"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_socket_close: invalid resource_id"));
    };

    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_socket_close: resource not found"));
    };

    if (resource.type != .nl_socket) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_socket_close: not a netlink socket resource"));
    }

    resource_mgr.free(resource_id) catch {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_socket_close: failed to free resource"));
    };

    return common.okResponse(allocator, request.req_id);
}

pub fn handleNlSendBatch(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [socket_id, batch_id]
    if (request.args.items.len != 2) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_send_batch: expected 2 args (socket_id, batch_id)"));
    }

    const socket_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_send_batch: invalid socket_id"));
    };

    const batch_id = request.args.items[1].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_send_batch: invalid batch_id"));
    };

    // Get the socket resource
    const socket_resource = resource_mgr.get(socket_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_send_batch: invalid socket resource"));
    };

    if (socket_resource.type != .nl_socket) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_send_batch: resource is not a netlink socket"));
    }

    // Get the batch resource
    const batch_resource = resource_mgr.get(batch_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_send_batch: invalid batch resource"));
    };

    if (batch_resource.type != .batch) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_send_batch: resource is not a batch"));
    }

    // Get buffer directly from batch
    const buf = libnftnl.batchBuffer(batch_resource.ptr);
    const buf_len = libnftnl.batchBufferLen(batch_resource.ptr);

    // Send the buffer via netlink socket
    const bytes_sent = libnftnl.nlSocketSend(socket_resource.ptr, buf, buf_len);
    if (bytes_sent < 0) {
        const err_msg = try std.fmt.allocPrint(allocator, "nl_send_batch: send failed with error code {d}", .{bytes_sent});
        return common.errorResponse(allocator, request.req_id, err_msg);
    }

    // Return the number of bytes sent
    return common.okValueResponse(allocator, request.req_id, @intCast(bytes_sent));
}

pub fn handleNlRecv(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [socket_id, buffer_size]
    if (request.args.items.len != 2) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_recv: expected 2 args (socket_id, buffer_size)"));
    }

    const socket_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_recv: invalid socket_id"));
    };

    const buffer_size = request.args.items[1].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_recv: invalid buffer_size"));
    };

    // Validate buffer size (max 64KB for safety)
    if (buffer_size > 65536) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_recv: buffer_size too large (max 64KB)"));
    }

    // Get socket resource
    const socket_resource = resource_mgr.get(socket_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_recv: socket resource not found"));
    };

    if (socket_resource.type != .nl_socket) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_recv: not a netlink socket resource"));
    }

    // Allocate buffer for receiving
    const recv_buf = try allocator.alloc(u8, @intCast(buffer_size));
    defer allocator.free(recv_buf);

    // Receive from netlink socket
    const received = libnftnl.nlSocketRecvfrom(socket_resource.ptr, recv_buf.ptr, recv_buf.len);
    if (received < 0) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_recv: failed to receive from socket"));
    }

    // Return the received data as binary
    const data_copy = try allocator.dupe(u8, recv_buf[0..@intCast(received)]);
    return protocol.Response{
        .allocator = allocator,
        .req_id = request.req_id,
        .payload = .{ .ok_binary = data_copy },
    };
}

pub fn handleNlParseError(
    allocator: std.mem.Allocator,
    request: protocol.Request,
) !protocol.Response {
    // Expected args: [binary_data]
    if (request.args.items.len != 1) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_parse_error: expected 1 arg (binary_data)"));
    }

    const binary_data = request.args.items[0].asBinary() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_parse_error: invalid binary data"));
    };

    // Check if this is an error message
    if (!netlink_errors.isError(binary_data)) {
        return common.okResponse(allocator, request.req_id);
    }

    // Parse the error code
    const err_code = netlink_errors.parseError(binary_data) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "nl_parse_error: failed to parse error message"));
    };

    // If error code is 0, it's a success ACK
    if (err_code == 0) {
        return common.okResponse(allocator, request.req_id);
    }

    // Send errno as integer to Elixir for decoding
    return common.errorErrnoResponse(allocator, request.req_id, err_code);
}

