import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const saveCase = mutation({
    args: {
        caseNumber: v.string(),
        caseType: v.optional(v.string()),
        platform: v.optional(v.string()),
        financialFraud: v.optional(v.string()),
        websiteInvolved: v.optional(v.string()),
        userId: v.string(),
        authorName: v.optional(v.string()),
    },
    handler: async (ctx, args) => {
        const id = await ctx.db.insert("cases", {
            caseNumber: args.caseNumber,
            caseType: args.caseType ?? "",
            platform: args.platform ?? "",
            financialFraud: args.financialFraud ?? "",
            websiteInvolved: args.websiteInvolved ?? "",
            userId: args.userId,
            authorName: args.authorName ?? "",
            createdAt: Date.now(),
        });
        return id;
    },
});

export const updateCase = mutation({
    args: {
        caseNumber: v.string(),
        userId: v.string(),
        caseType: v.string(),
        platform: v.string(),
        financialFraud: v.string(),
        websiteInvolved: v.string(),
    },
    handler: async (ctx, args) => {
        const existing = await ctx.db
            .query("cases")
            .withIndex("by_case_number", (q) => q.eq("caseNumber", args.caseNumber))
            .first();
        if (existing && existing.userId === args.userId) {
            await ctx.db.patch(existing._id, {
                caseType: args.caseType,
                platform: args.platform,
                financialFraud: args.financialFraud,
                websiteInvolved: args.websiteInvolved,
            });
            return existing._id;
        }
        return null;
    },
});

export const clearUserCases = mutation({
    args: {
        userId: v.string(),
    },
    handler: async (ctx, args) => {
        const cases = await ctx.db
            .query("cases")
            .withIndex("by_user", (q) => q.eq("userId", args.userId))
            .collect();
        for (const c of cases) {
            await ctx.db.delete(c._id);
        }
        return cases.length;
    },
});
