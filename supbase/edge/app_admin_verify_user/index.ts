import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_SECRET_KEYS = Deno.env.get("SUPABASE_SECRET_KEYS");
const ADMIN_VERIFY_SECRET = Deno.env.get("ADMIN_VERIFY_SECRET");

console.log("[STARTUP] app_admin_verify_user starting", {
  supabaseUrlConfigured: !!SUPABASE_URL,
  supabaseSecretKeysConfigured: !!SUPABASE_SECRET_KEYS,
  adminVerifySecretConfigured: !!ADMIN_VERIFY_SECRET,
});

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

console.log("[STARTUP] Supabase admin client ready:", !!supabaseAdmin);

interface VerifyUserPayload {
  email?: string;
}

Deno.serve(async (req: Request) => {
  const requestId = crypto.randomUUID();
  console.log(`[${requestId}] Request received`, {
    method: req.method,
    url: req.url,
    contentType: req.headers.get("content-type"),
    hasAuthorizationHeader: req.headers.has("authorization"),
    hasAdminSecretHeader: req.headers.has("x-admin-secret"),
  });

  if (req.method === "OPTIONS") {
    console.log(`[${requestId}] CORS preflight accepted`);
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    console.warn(`[${requestId}] Rejected unsupported method:`, req.method);
    return json({ success: false, error: "Only POST method is allowed" }, 405);
  }

  if (!supabaseAdmin) {
    console.error(`[${requestId}] [CONFIG ERROR] Supabase admin client is not configured`);
    return json({ success: false, error: "Server configuration error" }, 500);
  }

  if (!ADMIN_VERIFY_SECRET) {
    console.error(`[${requestId}] [CONFIG ERROR] ADMIN_VERIFY_SECRET is missing`);
    return json({ success: false, error: "Server configuration error" }, 500);
  }

  const suppliedSecret = req.headers.get("x-admin-secret");
  if (!suppliedSecret) {
    console.warn(`[${requestId}] [AUTH] x-admin-secret header is missing`);
    return json({ success: false, error: "Unauthorized" }, 401);
  }

  if (suppliedSecret !== ADMIN_VERIFY_SECRET) {
    console.warn(`[${requestId}] [AUTH] x-admin-secret header does not match configured secret`, {
      suppliedLength: suppliedSecret.length,
      configuredLength: ADMIN_VERIFY_SECRET.length,
    });
    return json({ success: false, error: "Unauthorized" }, 401);
  }

  console.log(`[${requestId}] [AUTH] Admin secret accepted`);

  try {
    const body = (await req.json()) as VerifyUserPayload;
    const email = body.email?.trim().toLowerCase();

    console.log(`[${requestId}] [VALIDATION] Payload parsed`, {
      email,
      emailProvided: !!email,
    });

    if (!email) {
      console.warn(`[${requestId}] [VALIDATION] Email is missing`);
      return json({ success: false, error: "email is required" }, 400);
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.warn(`[${requestId}] [VALIDATION] Email format is invalid`);
      return json({ success: false, error: "Invalid email address" }, 400);
    }

    console.log(`[${requestId}] [DATABASE] Looking up profile for:`, email);

    const { data: profile, error: profileError } = await supabaseAdmin
      .from("jn_users")
      .select("auth_user_id, email_id")
      .eq("email_id", email)
      .maybeSingle();

    if (profileError) {
      console.error(`[${requestId}] [DATABASE ERROR] Unable to find user profile`, profileError);
      return json({ success: false, error: "Unable to find user" }, 500);
    }

    if (!profile) {
      console.warn(`[${requestId}] [DATABASE] User profile not found for:`, email);
      return json({ success: false, error: "User not found" }, 404);
    }

    console.log(`[${requestId}] [AUTH] Confirming Auth user:`, profile.auth_user_id);

    const { data, error: updateError } =
      await supabaseAdmin.auth.admin.updateUserById(profile.auth_user_id, {
        email_confirm: true,
      });

    if (updateError) {
      console.error(`[${requestId}] [AUTH ERROR] Unable to verify user`, updateError);
      return json({ success: false, error: "Unable to verify user" }, 400);
    }

    const verifiedAt = new Date().toISOString();
    console.log(`[${requestId}] [DATABASE] Updating email verification fields`, {
      authUserId: profile.auth_user_id,
      verifiedAt,
    });

    const { data: updatedProfile, error: profileUpdateError } = await supabaseAdmin
      .from("jn_users")
      .update({
        email_verified_flag: 1,
        email_verified_at: verifiedAt,
      })
      .eq("auth_user_id", profile.auth_user_id)
      .select(
        "user_id, auth_user_id, email_id, email_verified_flag, email_verified_at",
      )
      .single();

    if (profileUpdateError) {
      console.error(
        `[${requestId}] [DATABASE ERROR] Auth email was confirmed, but the profile could not be updated`,
        profileUpdateError,
      );
      return json(
        {
          success: false,
          error: "Email was confirmed in Auth, but the user profile could not be updated",
        },
        500,
      );
    }

    console.log(`[${requestId}] [SUCCESS] Email verified`, {
      authUserId: data.user.id,
      userId: updatedProfile.user_id,
    });

    return json(
      {
        success: true,
        message: "Email verified successfully",
        user: {
          id: data.user.id,
          email: data.user.email,
          email_confirmed_at: data.user.email_confirmed_at,
          email_verified_flag: updatedProfile.email_verified_flag,
          email_verified_at: updatedProfile.email_verified_at,
        },
      },
      200,
    );
  } catch (error) {
    console.error(`[${requestId}] [FATAL ERROR]`, error);
    return json(
      {
        success: false,
        error: error instanceof SyntaxError ? "Invalid JSON body" : "Internal server error",
      },
      error instanceof SyntaxError ? 400 : 500,
    );
  }
});
