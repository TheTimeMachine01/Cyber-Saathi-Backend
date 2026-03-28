import { mutation } from "./_generated/server";
import { v } from "convex/values";

export const logAnalysis = mutation({
  args: {
    userId: v.string(),
    indicator: v.string(),
    mode: v.string(),
    results: v.any(),
  },
  handler: async (ctx, args) => {
    const logId = await ctx.db.insert("analysis_logs", {
      userId: args.userId,
      indicator: args.indicator,
      mode: args.mode,
      results: args.results,
      createdAt: Date.now(),
    });
    return logId;
  },
});
