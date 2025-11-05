const std = @import("std");
const libnftnl = @import("libnftnl.zig");

/// Resource types that can be managed
pub const ResourceType = enum {
    table,
    chain,
    rule,
    expr,
    set,
    set_elem,
    batch,
    nl_socket,
};

/// A tracked resource with its type and pointer
pub const Resource = struct {
    id: ResourceId,
    type: ResourceType,
    ptr: *anyopaque,
    // For expressions, store the expression type name (e.g., "payload", "cmp", etc.)
    // This is needed to correctly map attribute names to attribute IDs
    expr_type_name: ?[]const u8 = null,
};

pub const ResourceId = u64;

/// Manages libnftnl object lifetimes
pub const ResourceManager = struct {
    allocator: std.mem.Allocator,
    next_id: ResourceId,
    resources: std.AutoHashMap(ResourceId, Resource),

    pub fn init(allocator: std.mem.Allocator) ResourceManager {
        return .{
            .allocator = allocator,
            .next_id = 1,
            .resources = std.AutoHashMap(ResourceId, Resource).init(allocator),
        };
    }

    pub fn deinit(self: *ResourceManager) void {
        // Free all remaining resources
        var iter = self.resources.valueIterator();
        while (iter.next()) |resource| {
            self.freeResourceByType(resource.*) catch |err| {
                std.debug.print("Error freeing resource {}: {}\n", .{ resource.id, err });
            };
        }
        self.resources.deinit();
    }

    /// Allocate a new resource ID and track the pointer
    pub fn allocate(self: *ResourceManager, resource_type: ResourceType, ptr: *anyopaque) !ResourceId {
        const id = self.next_id;
        self.next_id += 1;

        try self.resources.put(id, .{
            .id = id,
            .type = resource_type,
            .ptr = ptr,
        });

        return id;
    }

    /// Allocate a new expression resource with its type name
    pub fn allocateExpr(self: *ResourceManager, ptr: *anyopaque, expr_type_name: []const u8) !ResourceId {
        const id = self.next_id;
        self.next_id += 1;

        // Duplicate the expression type name so it persists
        const name_copy = try self.allocator.dupe(u8, expr_type_name);

        try self.resources.put(id, .{
            .id = id,
            .type = .expr,
            .ptr = ptr,
            .expr_type_name = name_copy,
        });

        return id;
    }

    /// Get a resource by ID
    pub fn get(self: *ResourceManager, id: ResourceId) ?Resource {
        return self.resources.get(id);
    }

    /// Free a resource by ID
    pub fn free(self: *ResourceManager, id: ResourceId) !void {
        if (self.resources.fetchRemove(id)) |entry| {
            try self.freeResourceByType(entry.value);
        } else {
            return error.InvalidResourceId;
        }
    }

    /// Release a resource from tracking without freeing it.
    /// Use this when ownership of the resource is transferred elsewhere
    /// (e.g., when an expression is added to a rule).
    pub fn release(self: *ResourceManager, id: ResourceId) !void {
        if (self.resources.fetchRemove(id)) |entry| {
            // Free the expression type name if it was allocated, but not the pointer
            if (entry.value.type == .expr) {
                if (entry.value.expr_type_name) |name| {
                    self.allocator.free(name);
                }
            }
        } else {
            return error.InvalidResourceId;
        }
    }

    /// Free a resource based on its type
    fn freeResourceByType(self: *ResourceManager, resource: Resource) !void {
        switch (resource.type) {
            .table => libnftnl.tableFree(resource.ptr),
            .chain => libnftnl.chainFree(resource.ptr),
            .rule => libnftnl.ruleFree(resource.ptr),
            .expr => {
                libnftnl.exprFree(resource.ptr);
                // Free the expression type name if it was allocated
                if (resource.expr_type_name) |name| {
                    self.allocator.free(name);
                }
            },
            .set => libnftnl.setFree(resource.ptr),
            .set_elem => libnftnl.setElemFree(resource.ptr),
            .batch => libnftnl.batchFree(resource.ptr),
            .nl_socket => libnftnl.nlSocketClose(resource.ptr),
        }
    }

    /// Get the count of tracked resources
    pub fn count(self: *ResourceManager) usize {
        return self.resources.count();
    }
};
