import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_SECRET_KEYS = Deno.env.get("SUPABASE_SECRET_KEYS");
const ADMIN_VERIFY_SECRET = Deno.env.get("ADMIN_VERIFY_SECRET");

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-admin-secret, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};

function json(body: Record<string, unknown>, status: number) {
  return Response.json(body, { status, headers: corsHeaders });
}

function getSecretKey(): string | undefined {
  if (!SUPABASE_SECRET_KEYS) return undefined;

  try {
    const keys = JSON.parse(SUPABASE_SECRET_KEYS) as Record<string, unknown>;
    return typeof keys.default === "string" ? keys.default : undefined;
  } catch (error) {
    console.error("[STARTUP ERROR] Unable to parse SUPABASE_SECRET_KEYS", error);
    return undefined;
  }
}

const supabaseSecretKey = getSecretKey();
const supabaseAdmin = SUPABASE_URL && supabaseSecretKey
  ? createClient(SUPABASE_URL, supabaseSecretKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    })
  : null;

console.log("[STARTUP] app_admin_users_list", {
  supabaseAdminReady: !!supabaseAdmin,
  adminSecretConfigured: !!ADMIN_VERIFY_SECRET,
});

Deno.serve(async (req: Request) => {
  const requestId = crypto.randomUUID();
  console.log(`[${requestId}] Request received`, {
    method: req.method,
    hasAdminSecretHeader: req.headers.has("x-admin-secret"),
  });

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "GET") {
    return json({ success: false, error: "Only GET method is allowed" }, 405);
  }

  if (!supabaseAdmin || !ADMIN_VERIFY_SECRET) {
    console.error(`[${requestId}] Server environment is not configured`);
    return json({ success: false, error: "Server configuration error" }, 500);
  }

  const suppliedSecret = req.headers.get("x-admin-secret");
  if (!suppliedSecret || suppliedSecret !== ADMIN_VERIFY_SECRET) {
    console.warn(`[${requestId}] Unauthorized admin request`, {
      headerProvided: !!suppliedSecret,
    });
    return json({ success: false, error: "Unauthorized" }, 401);
  }

  try {
    const url = new URL(req.url);
    const page = Math.max(1, Number.parseInt(url.searchParams.get("page") ?? "1", 10) || 1);
    const requestedPageSize =
      Number.parseInt(url.searchParams.get("page_size") ?? "20", 10) || 20;
    const pageSize = Math.min(100, Math.max(1, requestedPageSize));
    const search = url.searchParams.get("search")?.trim() ?? "";
    const from = (page - 1) * pageSize;
    const to = from + pageSize - 1;

    console.log(`[${requestId}] Fetching users`, { page, pageSize, hasSearch: !!search });

    let query = supabaseAdmin
      .from("jn_users")
      .select(
        "user_id, created_at, first_name, last_name, nick_name, batch_id, auth_user_id, email_id, email_verified_flag, email_verified_at",
        { count: "exact" },
      );

    if (search) {
      const safeSearch = search.replace(/[^\p{L}\p{N}@._+\-\s]/gu, "").slice(0, 100);
      if (safeSearch) {
        query = query.or(
          `email_id.ilike.%${safeSearch}%,first_name.ilike.%${safeSearch}%,last_name.ilike.%${safeSearch}%,nick_name.ilike.%${safeSearch}%`,
        );
      }
    }

    const { data: users, error, count } = await query
      .order("created_at", { ascending: false })
      .range(from, to);

    if (error) {
      console.error(`[${requestId}] Database error`, error);
      return json({ success: false, error: "Unable to fetch users" }, 500);
    }

    const total = count ?? 0;
    console.log(`[${requestId}] Users fetched`, {
      returned: users.length,
      total,
    });

    return json(
      {
        success: true,
        users,
        pagination: {
          page,
          page_size: pageSize,
          total,
          total_pages: Math.ceil(total / pageSize),
        },
      },
      200,
    );
  } catch (error) {
    console.error(`[${requestId}] Unexpected error`, error);
    return json({ success: false, error: "Internal server error" }, 500);
  }
});
