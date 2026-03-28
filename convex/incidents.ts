import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

// ─── CREATE ────────────────────────────────────────────────────────────────────

/** Report a new cyber incident. userId/authorName passed explicitly from HTTP layer. */
export const reportScam = mutation({
    args: {
        title: v.string(),
        description: v.string(),
        category: v.optional(v.string()),
        severity: v.optional(v.string()),
        userId: v.string(),
        authorName: v.string(),
    },
    handler: async (ctx, args) => {
        const incidentId = await ctx.db.insert("incidents", {
            title: args.title,
            description: args.description,
            category: args.category ?? "other",
            severity: args.severity ?? "medium",
            status: "pending",
            userId: args.userId,
            authorName: args.authorName,
            createdAt: Date.now(),
        });
        return incidentId;
    },
});

// ─── READ ─────────────────────────────────────────────────────────────────────

/** List all incidents — public, most recent first. */
export const listAllIncidents = query({
    args: {},
    handler: async (ctx) => {
        const all = await ctx.db.query("incidents").collect();
        return all.sort((a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0));
    },
});

/** Fetch a single incident by its Convex document ID. */
export const getIncidentById = query({
    args: { id: v.id("incidents") },
    handler: async (ctx, args) => {
        return await ctx.db.get(args.id);
    },
});

/** Fetch incidents belonging to the currently signed-in user (auth required). */
export const getMyIncidents = query({
    args: {},
    handler: async (ctx) => {
        const identity = await ctx.auth.getUserIdentity();
        if (!identity) return [];

        const results = await ctx.db
            .query("incidents")
            .withIndex("by_user", (q) => q.eq("userId", identity.subject))
            .collect();

        return results.sort((a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0));
    },
});

// ─── UPDATE ───────────────────────────────────────────────────────────────────

/** Update status and/or severity of an incident. userId passed explicitly from HTTP layer for ownership check. */
export const updateIncident = mutation({
    args: {
        id: v.id("incidents"),
        userId: v.string(),
        status: v.optional(v.string()),
        severity: v.optional(v.string()),
        title: v.optional(v.string()),
        description: v.optional(v.string()),
    },
    handler: async (ctx, args) => {
        const incident = await ctx.db.get(args.id);
        if (!incident) throw new Error("Incident not found");
        if (incident.userId !== args.userId) throw new Error("Forbidden");

        const patch: Partial<typeof incident> = {};
        if (args.status !== undefined) patch.status = args.status;
        if (args.severity !== undefined) patch.severity = args.severity;
        if (args.title !== undefined) patch.title = args.title;
        if (args.description !== undefined) patch.description = args.description;

        await ctx.db.patch(args.id, patch);
        return { success: true };
    },
});

// ─── DELETE ───────────────────────────────────────────────────────────────────

/** Delete an incident by ID. userId passed explicitly from HTTP layer for ownership check. */
export const deleteIncident = mutation({
    args: { id: v.id("incidents"), userId: v.string() },
    handler: async (ctx, args) => {
        const incident = await ctx.db.get(args.id);
        if (!incident) throw new Error("Incident not found");
        if (incident.userId !== args.userId) throw new Error("Forbidden");

        await ctx.db.delete(args.id);
        return { success: true };
    },
});