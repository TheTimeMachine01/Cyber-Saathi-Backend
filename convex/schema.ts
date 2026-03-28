import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
    incidents: defineTable({
        title: v.string(),
        description: v.string(),
        category: v.optional(v.string()),  // e.g. "fraud", "phishing", "ransomware", "data_breach", "other"
        severity: v.optional(v.string()),  // "low", "medium", "high", "critical"
        status: v.string(),                // "pending", "investigating", "resolved"
        userId: v.string(),                // The Clerk 'sub' ID
        authorName: v.string(),
        createdAt: v.optional(v.number()), // Unix timestamp (ms)
    })
        .index("by_user", ["userId"])
        .index("by_status", ["status"])
        .index("by_severity", ["severity"]),

    cases: defineTable({
        caseNumber: v.string(),
        caseType: v.string(),
        platform: v.string(),
        financialFraud: v.string(),
        websiteInvolved: v.string(),
        userId: v.string(),
        authorName: v.string(),
        createdAt: v.optional(v.number()),
    }).index("by_user", ["userId"]).index("by_case_number", ["caseNumber"]),

    chat_messages: defineTable({
        userId: v.string(),
        role: v.string(), // "user" or "assistant"
        content: v.string(),
        createdAt: v.optional(v.number()),
    }).index("by_user", ["userId"]),

    analysis_logs: defineTable({
        userId: v.string(),
        indicator: v.string(), // The analyzed indicator or "Media File"
        mode: v.string(), // 'manual' or 'automation'
        results: v.any(), // Full JSON from Python Analysis
        createdAt: v.optional(v.number()),
    }).index("by_user", ["userId"]),
});