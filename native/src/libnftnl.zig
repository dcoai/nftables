const std = @import("std");

// C bindings for libnftnl library
// Made public so other modules can access C types
pub const c = @cImport({
    @cInclude("libnftnl/table.h");
    @cInclude("libnftnl/chain.h");
    @cInclude("libnftnl/rule.h");
    @cInclude("libnftnl/expr.h");
    @cInclude("libnftnl/set.h");
    @cInclude("libnftnl/batch.h");
    @cInclude("libmnl/libmnl.h");
    @cInclude("linux/netfilter/nfnetlink.h");
    @cInclude("linux/netfilter/nf_tables.h");
    @cInclude("linux/netlink.h");
    @cInclude("errno.h");
});


// Table operations

pub fn tableAlloc() !*anyopaque {
    const table = c.nftnl_table_alloc();
    if (table == null) {
        return error.AllocationFailed;
    }
    return @ptrCast(table);
}

pub fn tableFree(table: *anyopaque) void {
    c.nftnl_table_free(@ptrCast(@alignCast(table)));
}

pub fn tableSetStr(table: *anyopaque, attr: u16, value: [*:0]const u8) void {
    _ = c.nftnl_table_set_str(@ptrCast(@alignCast(table)), attr, value);
}

pub fn tableSetU32(table: *anyopaque, attr: u16, value: u32) void {
    _ = c.nftnl_table_set_u32(@ptrCast(@alignCast(table)), attr, value);
}

pub fn tableGetStr(table: *anyopaque, attr: u16) ?[*:0]const u8 {
    const result = c.nftnl_table_get_str(@ptrCast(@alignCast(table)), attr);
    if (result == null) {
        return null;
    }
    return result;
}

pub fn tableGetU32(table: *anyopaque, attr: u16) u32 {
    return c.nftnl_table_get_u32(@ptrCast(@alignCast(table)), attr);
}

pub fn tableNlmsgParse(nlh: *const anyopaque, table: *anyopaque) c_int {
    return c.nftnl_table_nlmsg_parse(@ptrCast(@alignCast(nlh)), @ptrCast(@alignCast(table)));
}

// Chain operations

pub fn chainAlloc() !*anyopaque {
    const chain = c.nftnl_chain_alloc();
    if (chain == null) {
        return error.AllocationFailed;
    }
    return @ptrCast(chain);
}

pub fn chainFree(chain: *anyopaque) void {
    c.nftnl_chain_free(@ptrCast(@alignCast(chain)));
}

pub fn chainSetStr(chain: *anyopaque, attr: u16, value: [*:0]const u8) void {
    _ = c.nftnl_chain_set_str(@ptrCast(@alignCast(chain)), attr, value);
}

pub fn chainSetU32(chain: *anyopaque, attr: u16, value: u32) void {
    _ = c.nftnl_chain_set_u32(@ptrCast(@alignCast(chain)), attr, value);
}

pub fn chainSetU8(chain: *anyopaque, attr: u16, value: u8) void {
    _ = c.nftnl_chain_set_u8(@ptrCast(@alignCast(chain)), attr, value);
}

pub fn chainGetStr(chain: *anyopaque, attr: u16) ?[*:0]const u8 {
    const result = c.nftnl_chain_get_str(@ptrCast(@alignCast(chain)), attr);
    if (result == null) {
        return null;
    }
    return result;
}

pub fn chainGetU32(chain: *anyopaque, attr: u16) u32 {
    return c.nftnl_chain_get_u32(@ptrCast(@alignCast(chain)), attr);
}

pub fn chainGetU8(chain: *anyopaque, attr: u16) u8 {
    return c.nftnl_chain_get_u8(@ptrCast(@alignCast(chain)), attr);
}

pub fn chainNlmsgParse(nlh: *const anyopaque, chain: *anyopaque) c_int {
    return c.nftnl_chain_nlmsg_parse(@ptrCast(@alignCast(nlh)), @ptrCast(@alignCast(chain)));
}

// Rule operations

pub fn ruleAlloc() !*anyopaque {
    const rule = c.nftnl_rule_alloc();
    if (rule == null) {
        return error.AllocationFailed;
    }
    return @ptrCast(rule);
}

pub fn ruleFree(rule: *anyopaque) void {
    c.nftnl_rule_free(@ptrCast(@alignCast(rule)));
}

pub fn ruleSetStr(rule: *anyopaque, attr: u16, value: [*:0]const u8) void {
    _ = c.nftnl_rule_set_str(@ptrCast(@alignCast(rule)), attr, value);
}

pub fn ruleSetU32(rule: *anyopaque, attr: u16, value: u32) void {
    _ = c.nftnl_rule_set_u32(@ptrCast(@alignCast(rule)), attr, value);
}

pub fn ruleSetU64(rule: *anyopaque, attr: u16, value: u64) void {
    _ = c.nftnl_rule_set_u64(@ptrCast(@alignCast(rule)), attr, value);
}

pub fn ruleAddExpr(rule: *anyopaque, expr: *anyopaque) void {
    c.nftnl_rule_add_expr(@ptrCast(@alignCast(rule)), @ptrCast(@alignCast(expr)));
}

pub fn ruleGetStr(rule: *anyopaque, attr: u16) ?[*:0]const u8 {
    const result = c.nftnl_rule_get_str(@ptrCast(@alignCast(rule)), attr);
    if (result == null) {
        return null;
    }
    return result;
}

pub fn ruleGetU32(rule: *anyopaque, attr: u16) u32 {
    return c.nftnl_rule_get_u32(@ptrCast(@alignCast(rule)), attr);
}

pub fn ruleGetU64(rule: *anyopaque, attr: u16) u64 {
    return c.nftnl_rule_get_u64(@ptrCast(@alignCast(rule)), attr);
}

pub fn ruleNlmsgParse(nlh: *const anyopaque, rule: *anyopaque) c_int {
    return c.nftnl_rule_nlmsg_parse(@ptrCast(@alignCast(nlh)), @ptrCast(@alignCast(rule)));
}

// Expression operations

pub fn exprAlloc(name: [*:0]const u8) !*anyopaque {
    const expr = c.nftnl_expr_alloc(name);
    if (expr == null) {
        return error.AllocationFailed;
    }
    return @ptrCast(expr);
}

pub fn exprFree(expr: *anyopaque) void {
    c.nftnl_expr_free(@ptrCast(@alignCast(expr)));
}

pub fn exprSetU8(expr: *anyopaque, attr: u16, value: u8) void {
    _ = c.nftnl_expr_set_u8(@ptrCast(@alignCast(expr)), attr, value);
}

pub fn exprSetU16(expr: *anyopaque, attr: u16, value: u16) void {
    _ = c.nftnl_expr_set_u16(@ptrCast(@alignCast(expr)), attr, value);
}

pub fn exprSetU32(expr: *anyopaque, attr: u16, value: u32) void {
    _ = c.nftnl_expr_set_u32(@ptrCast(@alignCast(expr)), attr, value);
}

pub fn exprSetU64(expr: *anyopaque, attr: u16, value: u64) void {
    _ = c.nftnl_expr_set_u64(@ptrCast(@alignCast(expr)), attr, value);
}

pub fn exprSetStr(expr: *anyopaque, attr: u16, value: [*:0]const u8) void {
    _ = c.nftnl_expr_set_str(@ptrCast(@alignCast(expr)), attr, value);
}

pub fn exprSet(expr: *anyopaque, attr: u16, data: *const anyopaque, data_len: u32) void {
    _ = c.nftnl_expr_set(@ptrCast(@alignCast(expr)), attr, data, data_len);
}

// Set operations

pub fn setAlloc() !*anyopaque {
    const set = c.nftnl_set_alloc();
    if (set == null) {
        return error.AllocationFailed;
    }
    return @ptrCast(set);
}

pub fn setFree(set: *anyopaque) void {
    c.nftnl_set_free(@ptrCast(@alignCast(set)));
}

pub fn setSetStr(set: *anyopaque, attr: u16, value: [*:0]const u8) void {
    _ = c.nftnl_set_set_str(@ptrCast(@alignCast(set)), attr, value);
}

pub fn setSetU32(set: *anyopaque, attr: u16, value: u32) void {
    _ = c.nftnl_set_set_u32(@ptrCast(@alignCast(set)), attr, value);
}

pub fn setSetU64(set: *anyopaque, attr: u16, value: u64) void {
    _ = c.nftnl_set_set_u64(@ptrCast(@alignCast(set)), attr, value);
}

pub fn setGetStr(set: *anyopaque, attr: u16) ?[*:0]const u8 {
    const result = c.nftnl_set_get_str(@ptrCast(@alignCast(set)), attr);
    if (result == null) {
        return null;
    }
    return result;
}

pub fn setGetU32(set: *anyopaque, attr: u16) u32 {
    return c.nftnl_set_get_u32(@ptrCast(@alignCast(set)), attr);
}

pub fn setGetU64(set: *anyopaque, attr: u16) u64 {
    return c.nftnl_set_get_u64(@ptrCast(@alignCast(set)), attr);
}

pub fn setNlmsgParse(nlh: *const anyopaque, set: *anyopaque) c_int {
    return c.nftnl_set_nlmsg_parse(@ptrCast(@alignCast(nlh)), @ptrCast(@alignCast(set)));
}

pub fn setElemAlloc() !*anyopaque {
    const elem = c.nftnl_set_elem_alloc();
    if (elem == null) {
        return error.AllocationFailed;
    }
    return @ptrCast(elem);
}

pub fn setElemFree(elem: *anyopaque) void {
    c.nftnl_set_elem_free(@ptrCast(@alignCast(elem)));
}

pub fn setElemSet(elem: *anyopaque, attr: u16, data: *const anyopaque, data_len: u32) c_int {
    return c.nftnl_set_elem_set(@ptrCast(@alignCast(elem)), attr, data, data_len);
}

pub fn setElemSetU32(elem: *anyopaque, attr: u16, value: u32) void {
    _ = c.nftnl_set_elem_set_u32(@ptrCast(@alignCast(elem)), attr, value);
}

pub fn setElemAdd(set: *anyopaque, elem: *anyopaque) void {
    c.nftnl_set_elem_add(@ptrCast(@alignCast(set)), @ptrCast(@alignCast(elem)));
}

pub fn setElemsNlmsgBuildPayload(nlh: *anyopaque, set: *anyopaque) void {
    c.nftnl_set_elems_nlmsg_build_payload(@ptrCast(@alignCast(nlh)), @ptrCast(@alignCast(set)));
}

pub fn setElemsNlmsgParse(nlh: *const anyopaque, set: *anyopaque) c_int {
    return c.nftnl_set_elems_nlmsg_parse(@ptrCast(@alignCast(nlh)), @ptrCast(@alignCast(set)));
}

// Set element iteration
pub fn setElemsIterCreate(set: *const anyopaque) ?*anyopaque {
    const iter = c.nftnl_set_elems_iter_create(@ptrCast(@alignCast(set)));
    if (iter == null) return null;
    return @ptrCast(@constCast(iter));
}

pub fn setElemsIterCur(iter: *const anyopaque) ?*anyopaque {
    const elem = c.nftnl_set_elems_iter_cur(@ptrCast(@alignCast(iter)));
    if (elem == null) return null;
    return @ptrCast(@constCast(elem));
}

pub fn setElemsIterNext(iter: *anyopaque) ?*anyopaque {
    const elem = c.nftnl_set_elems_iter_next(@ptrCast(@alignCast(iter)));
    if (elem == null) return null;
    return @ptrCast(@constCast(elem));
}

pub fn setElemsIterDestroy(iter: *anyopaque) void {
    c.nftnl_set_elems_iter_destroy(@ptrCast(@alignCast(iter)));
}

// Set element getters
pub fn setElemGet(elem: *anyopaque, attr: u16, data_len: *u32) ?*const anyopaque {
    const data = c.nftnl_set_elem_get(@ptrCast(@alignCast(elem)), attr, data_len);
    if (data == null) return null;
    return @ptrCast(data);
}

pub fn setElemGetU32(elem: *anyopaque, attr: u16) u32 {
    return c.nftnl_set_elem_get_u32(@ptrCast(@alignCast(elem)), attr);
}

pub fn setElemGetU64(elem: *anyopaque, attr: u16) u64 {
    return c.nftnl_set_elem_get_u64(@ptrCast(@alignCast(elem)), attr);
}

pub fn setElemIsSet(elem: *anyopaque, attr: u16) bool {
    return c.nftnl_set_elem_is_set(@ptrCast(@alignCast(elem)), attr);
}

// Batch operations

pub fn batchAlloc(page_size: u32, max_pages: u32) !*anyopaque {
    const batch = c.nftnl_batch_alloc(page_size, max_pages);
    if (batch == null) {
        return error.AllocationFailed;
    }
    return @ptrCast(batch);
}

pub fn batchFree(batch: *anyopaque) void {
    c.nftnl_batch_free(@ptrCast(@alignCast(batch)));
}

// Attribute constants (from libnftnl headers)
// Table attributes
pub const NFTNL_TABLE_NAME: u16 = 0;
pub const NFTNL_TABLE_FAMILY: u16 = 1;
pub const NFTNL_TABLE_FLAGS: u16 = 2;
pub const NFTNL_TABLE_USE: u16 = 3;

// Chain attributes
pub const NFTNL_CHAIN_NAME: u16 = 0;
pub const NFTNL_CHAIN_FAMILY: u16 = 1;
pub const NFTNL_CHAIN_TABLE: u16 = 2;
pub const NFTNL_CHAIN_HOOKNUM: u16 = 3;
pub const NFTNL_CHAIN_PRIO: u16 = 4;
pub const NFTNL_CHAIN_POLICY: u16 = 5;
pub const NFTNL_CHAIN_TYPE: u16 = 10;

// Rule attributes
pub const NFTNL_RULE_FAMILY: u16 = 0;
pub const NFTNL_RULE_TABLE: u16 = 1;
pub const NFTNL_RULE_CHAIN: u16 = 2;
pub const NFTNL_RULE_HANDLE: u16 = 3;
pub const NFTNL_RULE_COMPAT_PROTO: u16 = 4;
pub const NFTNL_RULE_COMPAT_FLAGS: u16 = 5;
pub const NFTNL_RULE_POSITION: u16 = 6;
pub const NFTNL_RULE_USERDATA: u16 = 7;
pub const NFTNL_RULE_ID: u16 = 8;
pub const NFTNL_RULE_POSITION_ID: u16 = 9;

// Set attributes
pub const NFTNL_SET_TABLE: u16 = 0;
pub const NFTNL_SET_NAME: u16 = 1;
pub const NFTNL_SET_FLAGS: u16 = 2;
pub const NFTNL_SET_KEY_TYPE: u16 = 3;
pub const NFTNL_SET_KEY_LEN: u16 = 4;
pub const NFTNL_SET_DATA_TYPE: u16 = 5;
pub const NFTNL_SET_DATA_LEN: u16 = 6;
pub const NFTNL_SET_FAMILY: u16 = 7;
pub const NFTNL_SET_ID: u16 = 8;
pub const NFTNL_SET_POLICY: u16 = 9;
pub const NFTNL_SET_DESC_SIZE: u16 = 10;

// Set element attributes (from libnftnl/set.h enum)
pub const NFTNL_SET_ELEM_FLAGS: u16 = 0;
pub const NFTNL_SET_ELEM_KEY: u16 = 1;
pub const NFTNL_SET_ELEM_VERDICT: u16 = 2;
pub const NFTNL_SET_ELEM_CHAIN: u16 = 3;
pub const NFTNL_SET_ELEM_DATA: u16 = 4;
pub const NFTNL_SET_ELEM_TIMEOUT: u16 = 5;

// Expression attributes - Base
pub const NFTNL_EXPR_NAME: u16 = 0;
pub const NFTNL_EXPR_BASE: u16 = 1;

// Payload expression
pub const NFTNL_EXPR_PAYLOAD_DREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_PAYLOAD_BASE: u16 = 2;
pub const NFTNL_EXPR_PAYLOAD_OFFSET: u16 = 3;
pub const NFTNL_EXPR_PAYLOAD_LEN: u16 = 4;
pub const NFTNL_EXPR_PAYLOAD_SREG: u16 = 5;
pub const NFTNL_EXPR_PAYLOAD_CSUM_TYPE: u16 = 6;
pub const NFTNL_EXPR_PAYLOAD_CSUM_OFFSET: u16 = 7;
pub const NFTNL_EXPR_PAYLOAD_FLAGS: u16 = 8;

// Numgen expression
pub const NFTNL_EXPR_NG_DREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_NG_MODULUS: u16 = 2;
pub const NFTNL_EXPR_NG_TYPE: u16 = 3;
pub const NFTNL_EXPR_NG_OFFSET: u16 = 4;
pub const NFTNL_EXPR_NG_SET_NAME: u16 = 5; // deprecated
pub const NFTNL_EXPR_NG_SET_ID: u16 = 6; // deprecated

// Meta expression
pub const NFTNL_EXPR_META_KEY: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_META_DREG: u16 = 2;
pub const NFTNL_EXPR_META_SREG: u16 = 3;

// RT expression
pub const NFTNL_EXPR_RT_KEY: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_RT_DREG: u16 = 2;

// Socket expression
pub const NFTNL_EXPR_SOCKET_KEY: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_SOCKET_DREG: u16 = 2;
pub const NFTNL_EXPR_SOCKET_LEVEL: u16 = 3;

// Tunnel expression
pub const NFTNL_EXPR_TUNNEL_KEY: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_TUNNEL_DREG: u16 = 2;

// Comparison expression
pub const NFTNL_EXPR_CMP_SREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_CMP_OP: u16 = 2;
pub const NFTNL_EXPR_CMP_DATA: u16 = 3;

// Range expression
pub const NFTNL_EXPR_RANGE_SREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_RANGE_OP: u16 = 2;
pub const NFTNL_EXPR_RANGE_FROM_DATA: u16 = 3;
pub const NFTNL_EXPR_RANGE_TO_DATA: u16 = 4;

// Immediate expression
pub const NFTNL_EXPR_IMM_DREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_IMM_DATA: u16 = 2;
pub const NFTNL_EXPR_IMM_VERDICT: u16 = 3;
pub const NFTNL_EXPR_IMM_CHAIN: u16 = 4;
pub const NFTNL_EXPR_IMM_CHAIN_ID: u16 = 5;

// Counter expression
pub const NFTNL_EXPR_CTR_PACKETS: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_CTR_BYTES: u16 = 2;

// Connection limit expression
pub const NFTNL_EXPR_CONNLIMIT_COUNT: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_CONNLIMIT_FLAGS: u16 = 2;

// Bitwise expression
pub const NFTNL_EXPR_BITWISE_SREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_BITWISE_DREG: u16 = 2;
pub const NFTNL_EXPR_BITWISE_LEN: u16 = 3;
pub const NFTNL_EXPR_BITWISE_MASK: u16 = 4;
pub const NFTNL_EXPR_BITWISE_XOR: u16 = 5;
pub const NFTNL_EXPR_BITWISE_OP: u16 = 6;
pub const NFTNL_EXPR_BITWISE_DATA: u16 = 7;
pub const NFTNL_EXPR_BITWISE_SREG2: u16 = 8;

// Target expression (iptables compat)
pub const NFTNL_EXPR_TG_NAME: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_TG_REV: u16 = 2;
pub const NFTNL_EXPR_TG_INFO: u16 = 3;

// Match expression (iptables compat)
pub const NFTNL_EXPR_MT_NAME: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_MT_REV: u16 = 2;
pub const NFTNL_EXPR_MT_INFO: u16 = 3;

// NAT expression
pub const NFTNL_EXPR_NAT_TYPE: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_NAT_FAMILY: u16 = 2;
pub const NFTNL_EXPR_NAT_REG_ADDR_MIN: u16 = 3;
pub const NFTNL_EXPR_NAT_REG_ADDR_MAX: u16 = 4;
pub const NFTNL_EXPR_NAT_REG_PROTO_MIN: u16 = 5;
pub const NFTNL_EXPR_NAT_REG_PROTO_MAX: u16 = 6;
pub const NFTNL_EXPR_NAT_FLAGS: u16 = 7;

// Transparent proxy expression
pub const NFTNL_EXPR_TPROXY_FAMILY: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_TPROXY_REG_ADDR: u16 = 2;
pub const NFTNL_EXPR_TPROXY_REG_PORT: u16 = 3;

// Lookup expression
pub const NFTNL_EXPR_LOOKUP_SREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_LOOKUP_DREG: u16 = 2;
pub const NFTNL_EXPR_LOOKUP_SET: u16 = 3;
pub const NFTNL_EXPR_LOOKUP_SET_ID: u16 = 4;
pub const NFTNL_EXPR_LOOKUP_FLAGS: u16 = 5;

// Dynset expression
pub const NFTNL_EXPR_DYNSET_SREG_KEY: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_DYNSET_SREG_DATA: u16 = 2;
pub const NFTNL_EXPR_DYNSET_OP: u16 = 3;
pub const NFTNL_EXPR_DYNSET_TIMEOUT: u16 = 4;
pub const NFTNL_EXPR_DYNSET_SET_NAME: u16 = 5;
pub const NFTNL_EXPR_DYNSET_SET_ID: u16 = 6;
pub const NFTNL_EXPR_DYNSET_EXPR: u16 = 7;
pub const NFTNL_EXPR_DYNSET_EXPRESSIONS: u16 = 8;
pub const NFTNL_EXPR_DYNSET_FLAGS: u16 = 9;

// Log expression
pub const NFTNL_EXPR_LOG_PREFIX: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_LOG_GROUP: u16 = 2;
pub const NFTNL_EXPR_LOG_SNAPLEN: u16 = 3;
pub const NFTNL_EXPR_LOG_QTHRESHOLD: u16 = 4;
pub const NFTNL_EXPR_LOG_LEVEL: u16 = 5;
pub const NFTNL_EXPR_LOG_FLAGS: u16 = 6;

// Extension header expression
pub const NFTNL_EXPR_EXTHDR_DREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_EXTHDR_TYPE: u16 = 2;
pub const NFTNL_EXPR_EXTHDR_OFFSET: u16 = 3;
pub const NFTNL_EXPR_EXTHDR_LEN: u16 = 4;
pub const NFTNL_EXPR_EXTHDR_FLAGS: u16 = 5;
pub const NFTNL_EXPR_EXTHDR_OP: u16 = 6;
pub const NFTNL_EXPR_EXTHDR_SREG: u16 = 7;

// Connection tracking expression
pub const NFTNL_EXPR_CT_DREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_CT_KEY: u16 = 2;
pub const NFTNL_EXPR_CT_DIR: u16 = 3;
pub const NFTNL_EXPR_CT_SREG: u16 = 4;

// Byteorder expression
pub const NFTNL_EXPR_BYTEORDER_DREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_BYTEORDER_SREG: u16 = 2;
pub const NFTNL_EXPR_BYTEORDER_OP: u16 = 3;
pub const NFTNL_EXPR_BYTEORDER_LEN: u16 = 4;
pub const NFTNL_EXPR_BYTEORDER_SIZE: u16 = 5;

// Limit expression
pub const NFTNL_EXPR_LIMIT_RATE: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_LIMIT_UNIT: u16 = 2;
pub const NFTNL_EXPR_LIMIT_BURST: u16 = 3;
pub const NFTNL_EXPR_LIMIT_TYPE: u16 = 4;
pub const NFTNL_EXPR_LIMIT_FLAGS: u16 = 5;

// Reject expression
pub const NFTNL_EXPR_REJECT_TYPE: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_REJECT_CODE: u16 = 2;

// Queue expression
pub const NFTNL_EXPR_QUEUE_NUM: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_QUEUE_TOTAL: u16 = 2;
pub const NFTNL_EXPR_QUEUE_FLAGS: u16 = 3;
pub const NFTNL_EXPR_QUEUE_SREG_QNUM: u16 = 4;

// Quota expression
pub const NFTNL_EXPR_QUOTA_BYTES: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_QUOTA_FLAGS: u16 = 2;
pub const NFTNL_EXPR_QUOTA_CONSUMED: u16 = 3;

// Masquerade expression
pub const NFTNL_EXPR_MASQ_FLAGS: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_MASQ_REG_PROTO_MIN: u16 = 2;
pub const NFTNL_EXPR_MASQ_REG_PROTO_MAX: u16 = 3;

// Redirect expression
pub const NFTNL_EXPR_REDIR_REG_PROTO_MIN: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_REDIR_REG_PROTO_MAX: u16 = 2;
pub const NFTNL_EXPR_REDIR_FLAGS: u16 = 3;

// Duplicate expression
pub const NFTNL_EXPR_DUP_SREG_ADDR: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_DUP_SREG_DEV: u16 = 2;

// Flow expression
pub const NFTNL_EXPR_FLOW_TABLE_NAME: u16 = NFTNL_EXPR_BASE;

// Forward expression
pub const NFTNL_EXPR_FWD_SREG_DEV: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_FWD_SREG_ADDR: u16 = 2;
pub const NFTNL_EXPR_FWD_NFPROTO: u16 = 3;

// Hash expression
pub const NFTNL_EXPR_HASH_SREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_HASH_DREG: u16 = 2;
pub const NFTNL_EXPR_HASH_LEN: u16 = 3;
pub const NFTNL_EXPR_HASH_MODULUS: u16 = 4;
pub const NFTNL_EXPR_HASH_SEED: u16 = 5;
pub const NFTNL_EXPR_HASH_OFFSET: u16 = 6;
pub const NFTNL_EXPR_HASH_TYPE: u16 = 7;
pub const NFTNL_EXPR_HASH_SET_NAME: u16 = 8; // deprecated
pub const NFTNL_EXPR_HASH_SET_ID: u16 = 9; // deprecated

// FIB expression
pub const NFTNL_EXPR_FIB_DREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_FIB_RESULT: u16 = 2;
pub const NFTNL_EXPR_FIB_FLAGS: u16 = 3;

// Object reference expression
pub const NFTNL_EXPR_OBJREF_IMM_TYPE: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_OBJREF_IMM_NAME: u16 = 2;
pub const NFTNL_EXPR_OBJREF_SET_SREG: u16 = 3;
pub const NFTNL_EXPR_OBJREF_SET_NAME: u16 = 4;
pub const NFTNL_EXPR_OBJREF_SET_ID: u16 = 5;

// OS fingerprint expression
pub const NFTNL_EXPR_OSF_DREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_OSF_TTL: u16 = 2;
pub const NFTNL_EXPR_OSF_FLAGS: u16 = 3;

// XFRM expression
pub const NFTNL_EXPR_XFRM_DREG: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_XFRM_SREG: u16 = 2;
pub const NFTNL_EXPR_XFRM_KEY: u16 = 3;
pub const NFTNL_EXPR_XFRM_DIR: u16 = 4;
pub const NFTNL_EXPR_XFRM_SPNUM: u16 = 5;

// Synproxy expression
pub const NFTNL_EXPR_SYNPROXY_MSS: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_SYNPROXY_WSCALE: u16 = 2;
pub const NFTNL_EXPR_SYNPROXY_FLAGS: u16 = 3;

// Last expression
pub const NFTNL_EXPR_LAST_MSECS: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_LAST_SET: u16 = 2;

// Inner expression
pub const NFTNL_EXPR_INNER_TYPE: u16 = NFTNL_EXPR_BASE;
pub const NFTNL_EXPR_INNER_FLAGS: u16 = 2;
pub const NFTNL_EXPR_INNER_HDRSIZE: u16 = 3;
pub const NFTNL_EXPR_INNER_EXPR: u16 = 4;

// Netlink message building

pub fn nlmsgBuildHdr(buf: *anyopaque, msg_type: u16, family: u16, flags: u16, seq: u32) *anyopaque {
    const nlh = c.nftnl_nlmsg_build_hdr(@ptrCast(@alignCast(buf)), msg_type, family, flags, seq);
    return @ptrCast(nlh);
}

pub fn tableNlmsgBuildPayload(nlh: *anyopaque, table: *anyopaque) void {
    c.nftnl_table_nlmsg_build_payload(@ptrCast(@alignCast(nlh)), @ptrCast(@alignCast(table)));
}

pub fn chainNlmsgBuildPayload(nlh: *anyopaque, chain: *anyopaque) void {
    c.nftnl_chain_nlmsg_build_payload(@ptrCast(@alignCast(nlh)), @ptrCast(@alignCast(chain)));
}

pub fn ruleNlmsgBuildPayload(nlh: *anyopaque, rule: *anyopaque) void {
    c.nftnl_rule_nlmsg_build_payload(@ptrCast(@alignCast(nlh)), @ptrCast(@alignCast(rule)));
}

pub fn setNlmsgBuildPayload(nlh: *anyopaque, set: *anyopaque) void {
    c.nftnl_set_nlmsg_build_payload(@ptrCast(@alignCast(nlh)), @ptrCast(@alignCast(set)));
}

pub fn setElemNlmsgBuildPayload(nlh: *anyopaque, set: *anyopaque) void {
    c.nftnl_set_elems_nlmsg_build_payload(@ptrCast(@alignCast(nlh)), @ptrCast(@alignCast(set)));
}

// Batch IOV operations

pub fn batchIovsize(batch: *anyopaque) c_int {
    return c.nftnl_batch_iovec_len(@ptrCast(@alignCast(batch)));
}

pub fn batchIov(batch: *anyopaque, iov: *anyopaque, iov_len: u32) void {
    c.nftnl_batch_iovec(@ptrCast(@alignCast(batch)), @ptrCast(@alignCast(iov)), iov_len);
}

pub fn batchBuffer(batch: *anyopaque) *anyopaque {
    return @ptrCast(c.nftnl_batch_buffer(@ptrCast(@alignCast(batch))));
}

pub fn batchBufferLen(batch: *anyopaque) u32 {
    return c.nftnl_batch_buffer_len(@ptrCast(@alignCast(batch)));
}

pub fn batchUpdate(batch: *anyopaque) c_int {
    return c.nftnl_batch_update(@ptrCast(@alignCast(batch)));
}

// MNL Batch operations (libmnl batch API - the correct way!)

pub fn mnlBatchStart(buf: [*]u8, buf_size: usize) *anyopaque {
    return @ptrCast(c.mnl_nlmsg_batch_start(buf, buf_size));
}

pub fn mnlBatchCurrent(batch: *anyopaque) *anyopaque {
    return @ptrCast(c.mnl_nlmsg_batch_current(@ptrCast(@alignCast(batch))));
}

pub fn mnlBatchNext(batch: *anyopaque) bool {
    return c.mnl_nlmsg_batch_next(@ptrCast(@alignCast(batch)));
}

pub fn mnlBatchHead(batch: *anyopaque) *anyopaque {
    return @ptrCast(c.mnl_nlmsg_batch_head(@ptrCast(@alignCast(batch))));
}

pub fn mnlBatchSize(batch: *anyopaque) usize {
    return c.mnl_nlmsg_batch_size(@ptrCast(@alignCast(batch)));
}

pub fn mnlBatchStop(batch: *anyopaque) void {
    c.mnl_nlmsg_batch_stop(@ptrCast(@alignCast(batch)));
}

// Netlink socket operations (libmnl)

pub fn nlSocketOpen(bus: c_int) ?*anyopaque {
    const nl = c.mnl_socket_open(bus);
    if (nl == null) {
        return null;
    }
    return @ptrCast(nl);
}

pub fn nlSocketBind(nl: *anyopaque, groups: c_uint, pid: c_int) c_int {
    return c.mnl_socket_bind(@ptrCast(@alignCast(nl)), groups, @intCast(pid));
}

pub fn nlSocketSend(nl: *anyopaque, buf: *const anyopaque, len: usize) isize {
    return c.mnl_socket_sendto(@ptrCast(@alignCast(nl)), buf, len);
}

pub fn nlSocketRecvfrom(nl: *anyopaque, buf: [*]u8, buf_size: usize) isize {
    return c.mnl_socket_recvfrom(@ptrCast(@alignCast(nl)), buf, buf_size);
}

pub fn nlSocketClose(nl: *anyopaque) void {
    _ = c.mnl_socket_close(@ptrCast(@alignCast(nl)));
}

pub fn nlSocketGetFd(nl: *anyopaque) c_int {
    return c.mnl_socket_get_fd(@ptrCast(@alignCast(nl)));
}

pub fn nlSocketGetPortid(nl: *anyopaque) c_uint {
    return c.mnl_socket_get_portid(@ptrCast(@alignCast(nl)));
}

// Message parsing

pub fn nlmsgGetPayloadLen(nlh: *const anyopaque) u32 {
    return c.mnl_nlmsg_get_payload_len(@ptrCast(@alignCast(nlh)));
}

pub fn nlmsgGetPayload(nlh: *const anyopaque) *anyopaque {
    return @ptrCast(c.mnl_nlmsg_get_payload(@ptrCast(@alignCast(nlh))));
}

pub fn nlmsgGetType(buf: [*]const u8) u16 {
    // nlmsghdr is at the start of the buffer
    // First field is nlmsg_len (u32), second is nlmsg_type (u16)
    const type_ptr: *align(1) const u16 = @ptrCast(buf + 4);
    return type_ptr.*;
}

// Netlink constants
pub const NETLINK_NETFILTER: c_int = 12;
pub const NFNETLINK_V0: u8 = 0;
pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;

// Netlink message alignment (must align to 4 bytes)
pub fn nlmsgAlign(len: u32) u32 {
    return (len + 3) & ~@as(u32, 3);
}

// NFT message types (WITHOUT subsystem - nftnl_nlmsg_build_hdr adds it!)
pub const NFT_MSG_NEWTABLE: u16 = 0;
pub const NFT_MSG_GETTABLE: u16 = 1;
pub const NFT_MSG_DELTABLE: u16 = 2;
pub const NFT_MSG_NEWCHAIN: u16 = 3;
pub const NFT_MSG_GETCHAIN: u16 = 4;
pub const NFT_MSG_DELCHAIN: u16 = 5;
pub const NFT_MSG_NEWRULE: u16 = 6;
pub const NFT_MSG_GETRULE: u16 = 7;
pub const NFT_MSG_DELRULE: u16 = 8;
pub const NFT_MSG_NEWSET: u16 = 9;
pub const NFT_MSG_GETSET: u16 = 10;
pub const NFT_MSG_DELSET: u16 = 11;
pub const NFT_MSG_NEWSETELEM: u16 = 12;
pub const NFT_MSG_GETSETELEM: u16 = 13;
pub const NFT_MSG_DELSETELEM: u16 = 14;

// Netlink message flags
pub const NLM_F_REQUEST: u16 = 1;
pub const NLM_F_ACK: u16 = 4;
pub const NLM_F_DUMP: u16 = 768;  // 0x300 (NLM_F_ROOT | NLM_F_MATCH)
pub const NLM_F_EXCL: u16 = 512;
pub const NLM_F_CREATE: u16 = 1024;
pub const NLM_F_APPEND: u16 = 2048;

// Message types for batch
pub const NFNL_MSG_BATCH_BEGIN: u16 = 16;
pub const NFNL_MSG_BATCH_END: u16 = 17;

/// Build batch begin message
pub fn batchBegin(buf: *anyopaque, seq: u32) *anyopaque {
    return @ptrCast(c.nftnl_batch_begin(@ptrCast(@alignCast(buf)), seq));
}

/// Build batch end message
pub fn batchEnd(buf: *anyopaque, seq: u32) *anyopaque {
    return @ptrCast(c.nftnl_batch_end(@ptrCast(@alignCast(buf)), seq));
}
