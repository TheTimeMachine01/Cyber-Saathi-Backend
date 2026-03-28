import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { api } from "./_generated/api";

const http = httpRouter();

// Helper: standard JSON response
const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
        status,
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
    });

// ─── CORS pre-flight ───────────────────────────────────────────────────────────
http.route({
    path: "/api/incidents",
    method: "OPTIONS",
    handler: httpAction(async () =>
        new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
        })
    ),
});

http.route({
    path: "/api/cases",
    method: "OPTIONS",
    handler: httpAction(async () =>
        new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
        })
    ),
});

http.route({
    path: "/api/chats",
    method: "OPTIONS",
    handler: httpAction(async () =>
        new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
        })
    ),
});

http.route({
    path: "/api/analysis",
    method: "OPTIONS",
    handler: httpAction(async () =>
        new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST,OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
        })
    ),
});

// ─── GET /api/health ──────────────────────────────────────────────────────────
http.route({
    path: "/api/health",
    method: "GET",
    handler: httpAction(async () =>
        json({ status: "ok", service: "cyber-saathi-api", timestamp: Date.now() })
    ),
});

// ─── POST /api/cases ──────────────────────────────────────────────────────
http.route({
    path: "/api/cases",
    method: "POST",
    handler: httpAction(async (ctx, request) => {
        // Auth is optional — use identity if token provided, otherwise use dev fallback
        const identity = await ctx.auth.getUserIdentity().catch(() => null);

        let body: any;
        try {
            body = await request.json();
        } catch {
            return json({ success: false, error: "Invalid JSON body" }, 400);
        }

        const { caseNumber, caseType, platform, financialFraud, websiteInvolved } = body;
        if (!caseNumber || !caseType) {
            return json({ success: false, error: "caseNumber and caseType are required" }, 400);
        }

        try {
            const id = await ctx.runMutation(api.cases.saveCase, {
                caseNumber,
                caseType,
                platform: platform ?? "unknown",
                financialFraud: financialFraud ?? "unknown",
                websiteInvolved: websiteInvolved ?? "unknown",
                userId: identity?.subject ?? "dev_user",
                authorName: identity?.name ?? "Dev Tester",
            });
            return json({ success: true, id }, 201);
        } catch (e: any) {
            return json({ success: false, error: e.message }, 500);
        }
    }),
});

// ─── POST /api/analysis ───────────────────────────────────────────────────
http.route({
    path: "/api/analysis",
    method: "POST",
    handler: httpAction(async (ctx, request) => {
        // Auth is optional — use identity if token provided, otherwise use dev fallback
        const identity = await ctx.auth.getUserIdentity().catch(() => null);

        let body: any;
        try {
            body = await request.json();
        } catch {
            return json({ success: false, error: "Invalid JSON body" }, 400);
        }

        const { indicator, mode, results } = body;
        if (!indicator || !mode) {
            return json({ success: false, error: "indicator and mode are required" }, 400);
        }

        try {
            const id = await ctx.runMutation(api.analysis.logAnalysis, {
                indicator,
                mode,
                results: results ?? {},
                userId: identity?.subject ?? "dev_user",
            });
            return json({ success: true, id }, 201);
        } catch (e: any) {
            return json({ success: false, error: e.message }, 500);
        }
    }),
});

// ─── GET /api/incidents ───────────────────────────────────────────────────────
http.route({
    path: "/api/incidents",
    method: "GET",
    handler: httpAction(async (ctx) => {
        try {
            const incidents = await ctx.runQuery(api.incidents.listAllIncidents, {});
            return json({ success: true, count: incidents.length, data: incidents });
        } catch (e: any) {
            return json({ success: false, error: e.message }, 500);
        }
    }),
});

// ─── POST /api/incidents ──────────────────────────────────────────────────────
http.route({
    path: "/api/incidents",
    method: "POST",
    handler: httpAction(async (ctx, request) => {
        // Auth is optional — use identity if token provided, otherwise use dev fallback
        const identity = await ctx.auth.getUserIdentity().catch(() => null);

        let body: any;
        try {
            body = await request.json();
        } catch {
            return json({ success: false, error: "Invalid JSON body" }, 400);
        }

        const { title, description, category, severity } = body;
        if (!title || !description) {
            return json({ success: false, error: "title and description are required" }, 400);
        }

        try {
            const id = await ctx.runMutation(api.incidents.reportScam, {
                title,
                description,
                category: category ?? "other",
                severity: severity ?? "medium",
                userId: identity?.subject ?? "dev_user",
                authorName: identity?.name ?? "Dev Tester",
            });
            return json({ success: true, id }, 201);
        } catch (e: any) {
            return json({ success: false, error: e.message }, 500);
        }
    }),
});

// ─── GET /api/incidents/:id ───────────────────────────────────────────────────
http.route({
    pathPrefix: "/api/incidents/",
    method: "GET",
    handler: httpAction(async (ctx, request) => {
        const url = new URL(request.url);
        const id = url.pathname.split("/api/incidents/")[1] as any;

        if (!id) return json({ success: false, error: "Missing incident ID" }, 400);

        try {
            const incident = await ctx.runQuery(api.incidents.getIncidentById, { id });
            if (!incident) return json({ success: false, error: "Incident not found" }, 404);
            return json({ success: true, data: incident });
        } catch (e: any) {
            return json({ success: false, error: e.message }, 500);
        }
    }),
});

// ─── PATCH /api/incidents/:id ─────────────────────────────────────────────────
http.route({
    pathPrefix: "/api/incidents/",
    method: "PATCH",
    handler: httpAction(async (ctx, request) => {
        const identity = await ctx.auth.getUserIdentity().catch(() => null);

        const url = new URL(request.url);
        const id = url.pathname.split("/api/incidents/")[1] as any;
        if (!id) return json({ success: false, error: "Missing incident ID" }, 400);

        let body: any;
        try {
            body = await request.json();
        } catch {
            return json({ success: false, error: "Invalid JSON body" }, 400);
        }

        try {
            const result = await ctx.runMutation(api.incidents.updateIncident, {
                id,
                status: body.status,
                severity: body.severity,
                title: body.title,
                description: body.description,
                userId: identity?.subject ?? "dev_user",
            });
            return json(result);
        } catch (e: any) {
            const status =
                e.message?.includes("Forbidden") ? 403 :
                    e.message?.includes("not found") ? 404 : 500;
            return json({ success: false, error: e.message }, status);
        }
    }),
});

// ─── DELETE /api/incidents/:id ────────────────────────────────────────────────
http.route({
    pathPrefix: "/api/incidents/",
    method: "DELETE",
    handler: httpAction(async (ctx, request) => {
        const identity = await ctx.auth.getUserIdentity().catch(() => null);

        const url = new URL(request.url);
        const id = url.pathname.split("/api/incidents/")[1] as any;
        if (!id) return json({ success: false, error: "Missing incident ID" }, 400);

        try {
            const result = await ctx.runMutation(api.incidents.deleteIncident, {
                id: id as any,
                userId: identity?.subject ?? "dev_user",
            });
            return json(result);
        } catch (e: any) {
            const status =
                e.message?.includes("Forbidden") ? 403 :
                    e.message?.includes("not found") ? 404 : 500;
            return json({ success: false, error: e.message }, status);
        }
    }),
});

// ─── GET /api/chats ───────────────────────────────────────────────────────────
http.route({
    path: "/api/chats",
    method: "GET",
    handler: httpAction(async (ctx, request) => {
        const identity = await ctx.auth.getUserIdentity().catch(() => null);
        const userId = identity?.subject ?? "dev_user";
        
        try {
            const messages = await ctx.runQuery(api.chats.getMessages, { userId });
            // Convex query is descending, reverse to get chronological order
            const chronologicalMessages = messages.reverse(); 
            return json({ success: true, count: chronologicalMessages.length, data: chronologicalMessages });
        } catch (e: any) {
            return json({ success: false, error: e.message }, 500);
        }
    }),
});

// ─── POST /api/chats ──────────────────────────────────────────────────────────
http.route({
    path: "/api/chats",
    method: "POST",
    handler: httpAction(async (ctx, request) => {
        const identity = await ctx.auth.getUserIdentity().catch(() => null);
        const userId = identity?.subject ?? "dev_user";

        let body: any;
        try {
            body = await request.json();
        } catch {
            return json({ success: false, error: "Invalid JSON body" }, 400);
        }

        const { role, content } = body;
        if (!role || !content) {
            return json({ success: false, error: "role and content are required" }, 400);
        }

        try {
            const id = await ctx.runMutation(api.chats.saveMessage, {
                userId,
                role,
                content,
            });
            return json({ success: true, id }, 201);
        } catch (e: any) {
            return json({ success: false, error: e.message }, 500);
        }
    }),
});

// ─── DELETE /api/cases ────────────────────────────────────────────────────────
http.route({
    path: "/api/cases",
    method: "DELETE",
    handler: httpAction(async (ctx, request) => {
        const identity = await ctx.auth.getUserIdentity().catch(() => null);
        const userId = identity?.subject ?? "dev_user";

        try {
            const deletedCount = await ctx.runMutation(api.cases.clearUserCases, { userId });
            return json({ success: true, deleted: deletedCount });
        } catch (e: any) {
            return json({ success: false, error: e.message }, 500);
        }
    }),
});

// ─── PATCH /api/cases ─────────────────────────────────────────────────────────
http.route({
    path: "/api/cases",
    method: "PATCH",
    handler: httpAction(async (ctx, request) => {
        const identity = await ctx.auth.getUserIdentity().catch(() => null);
        const userId = identity?.subject ?? "dev_user";

        let body: any;
        try {
            body = await request.json();
        } catch {
            return json({ success: false, error: "Invalid JSON body" }, 400);
        }

        const { caseNumber, caseType, platform, financialFraud, websiteInvolved } = body;
        if (!caseNumber) {
            return json({ success: false, error: "caseNumber is required" }, 400);
        }

        try {
            const id = await ctx.runMutation(api.cases.updateCase, {
                caseNumber,
                userId,
                caseType: caseType ?? "",
                platform: platform ?? "",
                financialFraud: financialFraud ?? "",
                websiteInvolved: websiteInvolved ?? "",
            });
            return json({ success: true, id });
        } catch (e: any) {
            return json({ success: false, error: e.message }, 500);
        }
    }),
});

export default http;