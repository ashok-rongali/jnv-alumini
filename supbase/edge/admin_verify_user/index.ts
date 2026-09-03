import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_SECRET_KEYS = Deno.env.get("SUPABASE_SECRET_KEYS");
const ADMIN_VERIFY_SECRET = Deno.env.get("ADMIN_VERIFY_SECRET");

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-admin-secret, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
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

interface VerifyUserPayload {
  email?: string;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return json({ success: false, error: "Only POST method is allowed" }, 405);
  }

  if (!supabaseAdmin) {
    console.error("[CONFIG ERROR] Supabase admin client is not configured");
    return json({ success: false, error: "Server configuration error" }, 500);
  }

  if (!ADMIN_VERIFY_SECRET) {
    console.error("[CONFIG ERROR] ADMIN_VERIFY_SECRET is missing");
    return json({ success: false, error: "Server configuration error" }, 500);
  }

  const suppliedSecret = req.headers.get("x-admin-secret");
  if (!suppliedSecret || suppliedSecret !== ADMIN_VERIFY_SECRET) {
    return json({ success: false, error: "Unauthorized" }, 401);
  }

  try {
    const body = (await req.json()) as VerifyUserPayload;
    const email = body.email?.trim().toLowerCase();

    if (!email) {
      return json({ success: false, error: "email is required" }, 400);
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return json({ success: false, error: "Invalid email address" }, 400);
    }

    const { data: profile, error: profileError } = await supabaseAdmin
      .from("jn_users")
      .select("auth_user_id, email_id")
      .eq("email_id", email)
      .maybeSingle();

    if (profileError) {
      console.error("[DATABASE ERROR] Unable to find user profile", profileError);
      return json({ success: false, error: "Unable to find user" }, 500);
    }

    if (!profile) {
      return json({ success: false, error: "User not found" }, 404);
    }

    const { data, error: updateError } =
      await supabaseAdmin.auth.admin.updateUserById(profile.auth_user_id, {
        email_confirm: true,
      });

    if (updateError) {
      console.error("[AUTH ERROR] Unable to verify user", updateError);
      return json({ success: false, error: "Unable to verify user" }, 400);
    }

    console.log("[SUCCESS] Email verified for Auth user", data.user.id);

    return json(
      {
        success: true,
        message: "Email verified successfully",
        user: {
          id: data.user.id,
          email: data.user.email,
          email_confirmed_at: data.user.email_confirmed_at,
        },
      },
      200,
    );
  } catch (error) {
    console.error("[FATAL ERROR]", error);
    return json(
      {
        success: false,
        error: error instanceof SyntaxError ? "Invalid JSON body" : "Internal server error",
      },
      error instanceof SyntaxError ? 400 : 500,
    );
  }
});
