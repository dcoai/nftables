const std = @import("std");
const protocol = @import("protocol.zig");
const resources = @import("resources.zig");

// Import command modules
const util = @import("commands/util.zig");
const table = @import("commands/table.zig");
const chain = @import("commands/chain.zig");
const rule = @import("commands/rule.zig");
const expr = @import("commands/expr.zig");
const set = @import("commands/set.zig");
const setelem = @import("commands/setelem.zig");
const batch = @import("commands/batch.zig");
const netlink = @import("commands/netlink.zig");
const query = @import("commands/query.zig");

// Re-export common response helpers for backward compatibility
const common = @import("commands/common.zig");
pub const errorResponse = common.errorResponse;
pub const okResponse = common.okResponse;
pub const okValueResponse = common.okValueResponse;

// Handler function type - some handlers don't need resource_mgr
const HandlerFn = *const fn (std.mem.Allocator, protocol.Request, *resources.ResourceManager) anyerror!protocol.Response;
const SimpleHandlerFn = *const fn (std.mem.Allocator, protocol.Request) anyerror!protocol.Response;

// Wrapper to make simple handlers compatible with the standard signature
fn wrapSimpleHandler(comptime handler: SimpleHandlerFn) HandlerFn {
    const Wrapper = struct {
        fn call(allocator: std.mem.Allocator, request: protocol.Request, _: *resources.ResourceManager) !protocol.Response {
            return handler(allocator, request);
        }
    };
    return Wrapper.call;
}

// Command dispatch table - O(1) lookup via compile-time hash map
const command_handlers = std.StaticStringMap(HandlerFn).initComptime(.{
    // Utility commands
    .{ "ping", wrapSimpleHandler(util.handlePing) },
    .{ "check_capabilities", wrapSimpleHandler(util.handleCheckCapabilities) },

    // Table commands
    .{ "table_alloc", table.handleTableAlloc },
    .{ "table_free", table.handleTableFree },
    .{ "table_set_str", table.handleTableSetStr },
    .{ "table_set_u32", table.handleTableSetU32 },
    .{ "table_get_str", table.handleTableGetStr },
    .{ "table_get_u32", table.handleTableGetU32 },
    .{ "table_send_to_kernel", table.handleTableSendToKernel },
    .{ "table_list", query.handleTableList },

    // Chain commands
    .{ "chain_alloc", chain.handleChainAlloc },
    .{ "chain_free", chain.handleChainFree },
    .{ "chain_set_str", chain.handleChainSetStr },
    .{ "chain_set_u32", chain.handleChainSetU32 },
    .{ "chain_set_u8", chain.handleChainSetU8 },
    .{ "chain_get_str", chain.handleChainGetStr },
    .{ "chain_get_u32", chain.handleChainGetU32 },
    .{ "chain_send_to_kernel", chain.handleChainSendToKernel },
    .{ "chain_list", query.handleChainList },

    // Rule commands
    .{ "rule_alloc", rule.handleRuleAlloc },
    .{ "rule_free", rule.handleRuleFree },
    .{ "rule_set_str", rule.handleRuleSetStr },
    .{ "rule_set_u32", rule.handleRuleSetU32 },
    .{ "rule_set_u64", rule.handleRuleSetU64 },
    .{ "rule_get_str", rule.handleRuleGetStr },
    .{ "rule_get_u32", rule.handleRuleGetU32 },
    .{ "rule_get_u64", rule.handleRuleGetU64 },
    .{ "rule_add_expr", rule.handleRuleAddExpr },
    .{ "rule_send_to_kernel", rule.handleRuleSendToKernel },
    .{ "rule_list", query.handleRuleList },

    // Expression commands
    .{ "expr_alloc", expr.handleExprAlloc },
    .{ "expr_free", expr.handleExprFree },
    .{ "expr_set_u8", expr.handleExprSetU8 },
    .{ "expr_set_u16", expr.handleExprSetU16 },
    .{ "expr_set_u32", expr.handleExprSetU32 },
    .{ "expr_set_u64", expr.handleExprSetU64 },
    .{ "expr_set_str", expr.handleExprSetStr },
    .{ "expr_set_data", expr.handleExprSetData },

    // Set commands
    .{ "set_alloc", set.handleSetAlloc },
    .{ "set_free", set.handleSetFree },
    .{ "set_set_str", set.handleSetSetStr },
    .{ "set_set_u32", set.handleSetSetU32 },
    .{ "set_send_to_kernel", set.handleSetSendToKernel },
    .{ "set_list", query.handleSetList },

    // Set element commands
    .{ "set_elem_alloc", setelem.handleSetElemAlloc },
    .{ "set_elem_free", setelem.handleSetElemFree },
    .{ "set_elem_set_data", setelem.handleSetElemSetData },
    .{ "set_elem_set_u32", setelem.handleSetElemSetU32 },
    .{ "set_elem_add", setelem.handleSetElemAdd },
    .{ "set_elem_send_to_kernel", setelem.handleSetElemSendToKernel },
    .{ "set_elem_list", query.handleSetElemList },

    // Batch commands
    .{ "batch_alloc", batch.handleBatchAlloc },
    .{ "batch_free", batch.handleBatchFree },

    // Netlink commands
    .{ "nl_socket_open", netlink.handleNlSocketOpen },
    .{ "nl_socket_close", netlink.handleNlSocketClose },
    .{ "nl_send_batch", netlink.handleNlSendBatch },
    .{ "nl_recv", netlink.handleNlRecv },
    .{ "nl_parse_error", wrapSimpleHandler(netlink.handleNlParseError) },
});

pub fn dispatch(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // O(1) hash lookup for command handler
    if (command_handlers.get(request.command)) |handler| {
        return handler(allocator, request, resource_mgr);
    } else {
        return errorResponse(allocator, request.req_id, try std.fmt.allocPrint(allocator, "unknown_command: {s}", .{request.command}));
    }
}
