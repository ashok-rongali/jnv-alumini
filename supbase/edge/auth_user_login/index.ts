import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

// ============================================================
// STARTUP LOGS
// ============================================================

console.log("=================================================");
console.log("JNV AUTH_LOGIN FUNCTION STARTING");
console.log("=================================================");

// ============================================================
// ENVIRONMENT
// ============================================================

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_SECRET_KEYS = Deno.env.get("SUPABASE_SECRET_KEYS");
const SUPABASE_PUBLISHABLE_KEYS = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS"); // anon-equivalent key, needed for password sign-in

console.log("[STARTUP] SUPABASE_URL exists:", !!SUPABASE_URL);
console.log("[STARTUP] SUPABASE_SECRET_KEYS exists:", !!SUPABASE_SECRET_KEYS);
console.log("[STARTUP] SUPABASE_PUBLISHABLE_KEYS exists:", !!SUPABASE_PUBLISHABLE_KEYS);

if (!SUPABASE_URL) {
  console.error("[STARTUP ERROR] SUPABASE_URL is missing");
}
if (!SUPABASE_SECRET_KEYS) {
  console.error("[STARTUP ERROR] SUPABASE_SECRET_KEYS is missing");
}
if (!SUPABASE_PUBLISHABLE_KEYS) {
  console.error("[STARTUP ERROR] SUPABASE_PUBLISHABLE_KEYS is missing");
}

// ============================================================
// PARSE KEYS
// ============================================================

let SUPABASE_SECRET_KEY: string | undefined;
let SUPABASE_PUBLISHABLE_KEY: string | undefined;

try {
  if (SUPABASE_SECRET_KEYS) {
    const secretKeys = JSON.parse(SUPABASE_SECRET_KEYS);
    console.log("[STARTUP] Secret key names:", Object.keys(secretKeys));
    SUPABASE_SECRET_KEY = secretKeys["default"];
    console.log("[STARTUP] Default secret key exists:", !!SUPABASE_SECRET_KEY);
  }
} catch (error) {
  console.error("[STARTUP ERROR] Unable to parse SUPABASE_SECRET_KEYS:", error);
}

try {
  if (SUPABASE_PUBLISHABLE_KEYS) {
    const pubKeys = JSON.parse(SUPABASE_PUBLISHABLE_KEYS);
    console.log("[STARTUP] Publishable key names:", Object.keys(pubKeys));
    SUPABASE_PUBLISHABLE_KEY = pubKeys["default"];
    console.log("[STARTUP] Default publishable key exists:", !!SUPABASE_PUBLISHABLE_KEY);
  }
} catch (error) {
  console.error("[STARTUP ERROR] Unable to parse SUPABASE_PUBLISHABLE_KEYS:", error);
}

// ============================================================
// CLIENTS
// ============================================================

// Admin client — used ONLY to read the jn_users profile row (bypasses RLS)
const supabaseAdmin = createClient(SUPABASE_URL!, SUPABASE_SECRET_KEY!);

// Auth client — used to actually verify the email/password via GoTrue.
// NOTE: signing in with the service/secret key also works technically,
// but using the publishable (anon-equivalent) key here mirrors what a
// real client app does and keeps the secret key scoped to admin-only calls.
const supabaseAuthClient = createClient(
  SUPABASE_URL!,
  SUPABASE_PUBLISHABLE_KEY ?? SUPABASE_SECRET_KEY!
);

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error("[STARTUP ERROR] Supabase admin client cannot be initialized");
}

// ============================================================
// REQUEST PAYLOAD
// ============================================================

interface LoginPayload {
  email: string;
  password: string;
}

// ============================================================
// CORS
// ============================================================

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

console.log("[STARTUP] JNV auth_login function ready");

// ============================================================
// API
// ============================================================

Deno.serve(async (req: Request) => {
  console.log("=================================================");
  console.log("[REQUEST] New request received");
  console.log("[REQUEST] Method:", req.method);
  console.log("[REQUEST] URL:", req.url);
  console.log("=================================================");

  if (req.method === "OPTIONS") {
    console.log("[REQUEST] OPTIONS request");
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    console.log("[REQUEST] Rejected - method is not POST");
    return Response.json(
      { success: false, error: "Only POST method is allowed" },
      { status: 405, headers: corsHeaders }
    );
  }

  try {
    // ========================================================
    // READ REQUEST BODY
    // ========================================================

    console.log("[REQUEST] Reading request body...");

    const body: LoginPayload = await req.json();

    console.log("[REQUEST] Payload received:", {
      email: body.email,
      passwordProvided: !!body.password,
    });

    // ========================================================
    // NORMALIZE + VALIDATE
    // ========================================================

    const email = body.email?.trim().toLowerCase();
    const password = body.password;

    if (!email || !password) {
      console.error("[VALIDATION ERROR] Required fields missing");
      return Response.json(
        { success: false, error: "email and password are required" },
        { status: 400, headers: corsHeaders }
      );
    }

    console.log("[VALIDATION] Validation successful");

    // ========================================================
    // SIGN IN VIA SUPABASE AUTH
    // ========================================================

    console.log("[AUTH] Attempting sign-in for:", email);

    const { data: signInData, error: signInError } =
      await supabaseAuthClient.auth.signInWithPassword({
        email,
        password,
      });

    if (signInError) {
      console.error("[AUTH ERROR]", {
        message: signInError.message,
        status: signInError.status,
        name: signInError.name,
      });

      // Keep the response generic so you don't leak whether the
      // email exists vs. the password was wrong.
      return Response.json(
        { success: false, error: "Invalid email or password" },
        { status: 401, headers: corsHeaders }
      );
    }

    const authUser = signInData.user;
    const session = signInData.session;

    if (!authUser || !session) {
      console.error("[AUTH ERROR] Sign-in succeeded but user/session missing");
      return Response.json(
        { success: false, error: "Unable to sign in" },
        { status: 500, headers: corsHeaders }
      );
    }

    console.log("[AUTH] Sign-in successful");
    console.log("[AUTH] Auth User ID:", authUser.id);

    // ========================================================
    // FETCH PROFILE FROM public.jn_users
    // ========================================================

    console.log("[DATABASE] Fetching profile from jn_users...");

    const { data: userData, error: userError } = await supabaseAdmin
      .from("jn_users")
      .select("*")
      .eq("auth_user_id", authUser.id)
      .single();

    if (userError) {
      console.error("[DATABASE ERROR]", {
        message: userError.message,
        details: userError.details,
        hint: userError.hint,
        code: userError.code,
      });

      return Response.json(
        { success: false, error: "User profile not found" },
        { status: 404, headers: corsHeaders }
      );
    }

    console.log("[DATABASE] Profile fetch successful");
    console.log("[SUCCESS] Login completed for user_id:", userData?.user_id);

    // ========================================================
    // RESPONSE
    // ========================================================

    return Response.json(
      {
        success: true,
        message: "Login successful",
        user: userData,
        session: {
          access_token: session.access_token,
          refresh_token: session.refresh_token,
          expires_at: session.expires_at,
        },
      },
      { status: 200, headers: corsHeaders }
    );
  } catch (error) {
    console.error("=================================================");
    console.error("[FATAL ERROR]", error);
    console.error("=================================================");

    return Response.json(
      {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500, headers: corsHeaders }
    );
  }
});