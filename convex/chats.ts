import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const saveMessage = mutation({
    args: {
        userId: v.string(),
        role: v.string(),
        content: v.string(),
    },
    handler: async (ctx, args) => {
        return await ctx.db.insert("chat_messages", {
            userId: args.userId,
            role: args.role,
            content: args.content,
            createdAt: Date.now(),
        });
    },
});

export const getMessages = query({
    args: {
        userId: v.string(),
    },
    handler: async (ctx, args) => {
        return await ctx.db
            .query("chat_messages")
            .withIndex("by_user", (q) => q.eq("userId", args.userId))
            .order("desc") // We'll reverse it on the client or fetch in desc and sort later
            .take(100);
    },
});
