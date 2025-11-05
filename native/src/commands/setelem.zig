const std = @import("std");
const protocol = @import("../protocol.zig");
const resources = @import("../resources.zig");
const libnftnl = @import("../libnftnl.zig");
const netlink_errors = @import("../netlink_errors.zig");
const common = @import("common.zig");

pub fn handleSetElemAlloc(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // No arguments expected
    if (request.args.items.len != 0) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_alloc: expected 0 args"));
    }

    const elem = libnftnl.setElemAlloc() catch |err| {
        const error_msg = try std.fmt.allocPrint(allocator, "set_elem_alloc_failed: {}", .{err});
        return common.errorResponse(allocator, request.req_id, error_msg);
    };

    const resource_id = try resource_mgr.allocate(.set_elem, elem);

    return common.okValueResponse(allocator, request.req_id, resource_id);
}

pub fn handleSetElemFree(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id]
    if (request.args.items.len != 1) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_free: expected 1 arg"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_free: invalid resource_id"));
    };

    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_free: resource not found"));
    };

    if (resource.type != .set_elem) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_free: not a set_elem resource"));
    }

    resource_mgr.free(resource_id) catch {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_free: failed to free resource"));
    };

    return common.okResponse(allocator, request.req_id);
}

pub fn handleSetElemSetData(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id, attr_atom, binary_data]
    if (request.args.items.len != 3) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_data: expected 3 args"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_data: invalid resource_id"));
    };

    const attr_name = request.args.items[1].asAtom() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_data: invalid attr"));
    };

    const data = request.args.items[2].asBinary() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_data: invalid data"));
    };

    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_data: resource not found"));
    };

    if (resource.type != .set_elem) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_data: not a set_elem resource"));
    }

    // Map attribute name to constant
    const attr_const: u16 = if (std.mem.eql(u8, attr_name, "key"))
        libnftnl.NFTNL_SET_ELEM_KEY
    else if (std.mem.eql(u8, attr_name, "data"))
        libnftnl.NFTNL_SET_ELEM_DATA
    else {
        return common.errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "set_elem_set_data: unknown attr '{s}'", .{attr_name}));
    };

    // nftnl_set_elem_set returns 0 on success, -1 on error
    const result = libnftnl.setElemSet(resource.ptr, attr_const, data.ptr, @intCast(data.len));
    if (result < 0) {
        return common.errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "set_elem_set_data: nftnl_set_elem_set failed with code {d}", .{result}));
    }

    return common.okResponse(allocator, request.req_id);
}

pub fn handleSetElemSetU32(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [resource_id, attr_atom, value_u32]
    if (request.args.items.len != 3) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_u32: expected 3 args"));
    }

    const resource_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_u32: invalid resource_id"));
    };

    const attr_name = request.args.items[1].asAtom() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_u32: invalid attr"));
    };

    const value = request.args.items[2].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_u32: invalid value"));
    };

    const resource = resource_mgr.get(resource_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_u32: resource not found"));
    };

    if (resource.type != .set_elem) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_set_u32: not a set_elem resource"));
    }

    // Map attribute name to constant
    const attr_const: u16 = if (std.mem.eql(u8, attr_name, "flags"))
        libnftnl.NFTNL_SET_ELEM_FLAGS
    else if (std.mem.eql(u8, attr_name, "timeout"))
        libnftnl.NFTNL_SET_ELEM_TIMEOUT
    else {
        return common.errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "set_elem_set_u32: unknown attr '{s}'", .{attr_name}));
    };

    libnftnl.setElemSetU32(resource.ptr, attr_const, @intCast(value));

    return common.okResponse(allocator, request.req_id);
}

pub fn handleSetElemAdd(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [set_id, elem_id]
    if (request.args.items.len != 2) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_add: expected 2 args"));
    }

    const set_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_add: invalid set_id"));
    };

    const elem_id = request.args.items[1].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_add: invalid elem_id"));
    };

    const set_resource = resource_mgr.get(set_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_add: set not found"));
    };

    const elem_resource = resource_mgr.get(elem_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_add: elem not found"));
    };

    if (set_resource.type != .set) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_add: not a set resource"));
    }

    if (elem_resource.type != .set_elem) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_add: not a set_elem resource"));
    }

    // Note: setElemAdd transfers ownership of the element to the set
    libnftnl.setElemAdd(set_resource.ptr, elem_resource.ptr);

    // Remove element from resource manager since ownership transferred to set
    // This prevents double-free at shutdown
    resource_mgr.release(elem_id) catch |err| {
        // This shouldn't fail since we just validated the elem_id exists
        return common.errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "set_elem_add: failed to release resource: {}", .{err}));
    };

    return common.okResponse(allocator, request.req_id);
}

// Batch operations

pub fn handleSetElemSendToKernel(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Expected args: [set_id, cmd, family]
    // cmd: "add" or "delete"
    // family: protocol family integer (2=inet, 10=inet6, etc.)
    // Note: The set must have elements added to it before sending
    if (request.args.items.len != 3) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: expected 3 args (set_id, cmd, family)"));
    }

    const set_id = request.args.items[0].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: invalid set_id"));
    };

    const cmd = request.args.items[1].asAtom() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: invalid cmd"));
    };

    const family_u64 = request.args.items[2].asU64() orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: invalid family"));
    };
    const family: u16 = @intCast(family_u64);

    // Get the set resource (contains elements to send)
    const set_resource = resource_mgr.get(set_id) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: invalid set resource"));
    };

    if (set_resource.type != .set) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: resource is not a set"));
    }

    // Determine the netlink message type
    const msg_type: u16 = if (std.mem.eql(u8, cmd, "add"))
        libnftnl.NFT_MSG_NEWSETELEM
    else if (std.mem.eql(u8, cmd, "delete"))
        libnftnl.NFT_MSG_DELSETELEM
    else {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: cmd must be 'add' or 'delete'"));
    };

    // Get and validate table and set names (family comes from parameter, not set object)
    const table_name = libnftnl.setGetStr(set_resource.ptr, libnftnl.NFTNL_SET_TABLE);
    const set_name = libnftnl.setGetStr(set_resource.ptr, libnftnl.NFTNL_SET_NAME);

    if (table_name == null) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: set must have table name set"));
    }

    if (set_name == null) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: set must have set name set"));
    }

    // Create a batch using MNL batch API (like the libnftnl example)
    // Buffer must be aligned to 8 bytes for netlink message headers on 64-bit systems
    var buf: [8192]u8 align(8) = undefined;
    const batch = libnftnl.mnlBatchStart(&buf, buf.len);
    defer libnftnl.mnlBatchStop(batch);

    // Sequence number for messages
    var seq: u32 = 1;

    // Build batch begin message
    const nlh_begin = libnftnl.batchBegin(libnftnl.mnlBatchCurrent(batch), seq);
    _ = nlh_begin;
    _ = libnftnl.mnlBatchNext(batch);
    seq += 1;

    // Build set element message
    // Flags needed: REQUEST (required for kernel requests), ACK (get response)
    // For add: also CREATE | EXCL (create only if doesn't exist)
    // For delete: no special flags needed
    const flags: u16 = libnftnl.NLM_F_REQUEST | libnftnl.NLM_F_ACK |
                       if (std.mem.eql(u8, cmd, "add"))
                           libnftnl.NLM_F_CREATE | libnftnl.NLM_F_EXCL
                       else
                           0;

    const nlh_setelem = libnftnl.nlmsgBuildHdr(
        libnftnl.mnlBatchCurrent(batch),
        msg_type,
        family,
        flags,
        seq
    );
    libnftnl.setElemNlmsgBuildPayload(nlh_setelem, set_resource.ptr);
    _ = libnftnl.mnlBatchNext(batch);
    seq += 1;

    // Build batch end message
    const nlh_end = libnftnl.batchEnd(libnftnl.mnlBatchCurrent(batch), seq);
    _ = nlh_end;
    _ = libnftnl.mnlBatchNext(batch);

    // Get the batch head and size
    const batch_head = libnftnl.mnlBatchHead(batch);
    const buf_len = libnftnl.mnlBatchSize(batch);

    // Open netlink socket
    const nl_socket = libnftnl.nlSocketOpen(libnftnl.NETLINK_NETFILTER) orelse {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: failed to open netlink socket"));
    };
    defer libnftnl.nlSocketClose(nl_socket);

    // Bind the socket
    if (libnftnl.nlSocketBind(nl_socket, 0, 0) < 0) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: failed to bind netlink socket"));
    }

    // Send the buffer via netlink socket
    const bytes_sent = libnftnl.nlSocketSend(nl_socket, batch_head, buf_len);
    if (bytes_sent < 0) {
        const err_msg = try std.fmt.allocPrint(allocator, "set_elem_send_to_kernel: send failed with error code {d}", .{bytes_sent});
        return common.errorResponse(allocator, request.req_id, err_msg);
    }

    // Receive response
    const recv_buf = try allocator.alloc(u8, 8192);
    defer allocator.free(recv_buf);

    const received = libnftnl.nlSocketRecvfrom(nl_socket, recv_buf.ptr, recv_buf.len);
    if (received < 0) {
        return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: failed to receive response"));
    }

    // Parse any errors in the response
    const response_data = recv_buf[0..@intCast(received)];

    if (netlink_errors.isError(response_data)) {
        const err_code = netlink_errors.parseError(response_data) orelse {
            return common.errorResponse(allocator, request.req_id, try allocator.dupe(u8, "set_elem_send_to_kernel: failed to parse error"));
        };

        if (err_code != 0) {
            return common.errorErrnoResponse(allocator, request.req_id, err_code);
        }
    }

    // Success
    return common.okResponse(allocator, request.req_id);
}
