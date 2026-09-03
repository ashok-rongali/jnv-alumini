import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

// ============================================================
// STARTUP LOGS
// ============================================================

console.log("=================================================");
console.log("JNV REGISTER_USER FUNCTION STARTING");
console.log("=================================================");

// ============================================================
// ENVIRONMENT
// ============================================================

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_SECRET_KEYS = Deno.env.get("SUPABASE_SECRET_KEYS");

console.log(
  "[STARTUP] SUPABASE_URL exists:",
  !!SUPABASE_URL
);

console.log(
  "[STARTUP] SUPABASE_SECRET_KEYS exists:",
  !!SUPABASE_SECRET_KEYS
);

if (!SUPABASE_URL) {
  console.error("[STARTUP ERROR] SUPABASE_URL is missing");
}

if (!SUPABASE_SECRET_KEYS) {
  console.error(
    "[STARTUP ERROR] SUPABASE_SECRET_KEYS is missing"
  );
}

// ============================================================
// GET SUPABASE SECRET KEY
// ============================================================

let SUPABASE_SECRET_KEY: string | undefined;

try {

  if (SUPABASE_SECRET_KEYS) {

    const secretKeys = JSON.parse(
      SUPABASE_SECRET_KEYS
    );

    console.log(
      "[STARTUP] Secret key names:",
      Object.keys(secretKeys)
    );

    SUPABASE_SECRET_KEY = secretKeys["default"];

    console.log(
      "[STARTUP] Default secret key exists:",
      !!SUPABASE_SECRET_KEY
    );
  }

} catch (error) {

  console.error(
    "[STARTUP ERROR] Unable to parse SUPABASE_SECRET_KEYS:",
    error
  );
}

// ============================================================
// SUPABASE ADMIN CLIENT
// ============================================================

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {

  console.error(
    "[STARTUP ERROR] Supabase admin client cannot be initialized"
  );
}

const supabaseAdmin = createClient(
  SUPABASE_URL!,
  SUPABASE_SECRET_KEY!
);

// ============================================================
// REQUEST PAYLOAD
// ============================================================

interface RegisterPayload {

  email: string;

  password: string;

  first_name: string;

  last_name?: string;

  nick_name?: string;

  batch_id?: string;
}

// ============================================================
// CORS
// ============================================================

const corsHeaders = {

  "Access-Control-Allow-Origin": "*",

  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",

  "Access-Control-Allow-Methods":
    "POST, OPTIONS",
};

// ============================================================
// FUNCTION READY
// ============================================================

console.log(
  "[STARTUP] JNV register_user function ready"
);

// ============================================================
// API
// ============================================================

Deno.serve(async (req: Request) => {

  console.log("=================================================");
  console.log("[REQUEST] New request received");
  console.log("[REQUEST] Method:", req.method);
  console.log("[REQUEST] URL:", req.url);
  console.log("=================================================");

  // ==========================================================
  // REQUEST HEADERS
  // ==========================================================

  console.log(
    "[REQUEST] Has apikey:",
    req.headers.has("apikey")
  );

  console.log(
    "[REQUEST] Has authorization:",
    req.headers.has("authorization")
  );

  console.log(
    "[REQUEST] Content-Type:",
    req.headers.get("content-type")
  );

  // ==========================================================
  // CORS
  // ==========================================================

  if (req.method === "OPTIONS") {

    console.log(
      "[REQUEST] OPTIONS request"
    );

    return new Response("ok", {
      headers: corsHeaders,
    });
  }

  // ==========================================================
  // POST ONLY
  // ==========================================================

  if (req.method !== "POST") {

    console.log(
      "[REQUEST] Rejected - method is not POST"
    );

    return Response.json(
      {
        success: false,
        error: "Only POST method is allowed",
      },
      {
        status: 405,
        headers: corsHeaders,
      }
    );
  }

  try {

    // ========================================================
    // READ REQUEST BODY
    // ========================================================

    console.log(
      "[REQUEST] Reading request body..."
    );

    const body: RegisterPayload = await req.json();

    console.log(
      "[REQUEST] Payload received:",
      {
        email: body.email,
        first_name: body.first_name,
        last_name: body.last_name,
        nick_name: body.nick_name,
        batch_id: body.batch_id,
        passwordProvided: !!body.password,
      }
    );

    // ========================================================
    // NORMALIZE VALUES
    // ========================================================

    const email = body.email
      ?.trim()
      .toLowerCase();

    const password = body.password;

    const first_name = body.first_name
      ?.trim();

    const last_name = body.last_name
      ?.trim() || null;

    const nick_name = body.nick_name
      ?.trim() || null;

    const batch_id = body.batch_id
      ?.trim() || null;

    // ========================================================
    // VALIDATION
    // ========================================================

    console.log(
      "[VALIDATION] Validating request..."
    );

    if (
      !email ||
      !password ||
      !first_name
    ) {

      console.error(
        "[VALIDATION ERROR] Required fields missing"
      );

      return Response.json(
        {
          success: false,
          error:
            "email, password and first_name are required",
        },
        {
          status: 400,
          headers: corsHeaders,
        }
      );
    }

    if (password.length < 6) {

      console.error(
        "[VALIDATION ERROR] Password too short"
      );

      return Response.json(
        {
          success: false,
          error:
            "Password must be at least 6 characters",
        },
        {
          status: 400,
          headers: corsHeaders,
        }
      );
    }

    // Basic email validation

    const emailRegex =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(email)) {

      console.error(
        "[VALIDATION ERROR] Invalid email"
      );

      return Response.json(
        {
          success: false,
          error: "Invalid email address",
        },
        {
          status: 400,
          headers: corsHeaders,
        }
      );
    }

    console.log(
      "[VALIDATION] Validation successful"
    );

    // ========================================================
    // CREATE SUPABASE AUTH USER
    // ========================================================

    console.log(
      "[AUTH] Creating Supabase Auth user:",
      email
    );

    const {
      data: authData,
      error: authError,
    } =
      await supabaseAdmin.auth.admin.createUser({

        email: email,

        password: password,

        email_confirm: false,
      });

    // ========================================================
    // AUTH ERROR
    // ========================================================

    if (authError) {

      console.error(
        "[AUTH ERROR]",
        {
          message: authError.message,
          status: authError.status,
          name: authError.name,
        }
      );

      return Response.json(
        {
          success: false,
          error: authError.message,
        },
        {
          status: 400,
          headers: corsHeaders,
        }
      );
    }

    // ========================================================
    // AUTH USER CHECK
    // ========================================================

    const authUser = authData.user;

    if (!authUser) {

      console.error(
        "[AUTH ERROR] Auth user was not returned"
      );

      return Response.json(
        {
          success: false,
          error:
            "Unable to create authentication user",
        },
        {
          status: 500,
          headers: corsHeaders,
        }
      );
    }

    console.log(
      "[AUTH] Auth user created successfully"
    );

    console.log(
      "[AUTH] Auth User ID:",
      authUser.id
    );

    // ========================================================
    // INSERT INTO public.jnv_users
    // ========================================================

    console.log(
      "[DATABASE] Inserting into public.jn_users..."
    );

    const {
      data: userData,
      error: userError,
    } =
      await supabaseAdmin
        .from("jn_users")
        .insert({
          auth_user_id: authUser.id,     // Supabase Auth UUID
          first_name: first_name,
          last_name: last_name,
          nick_name: nick_name,
          email_id: email,
          batch_id: batch_id,
          // PostgreSQL can generate this
          // if create_at has a DEFAULT
          // create_at: new Date().toISOString(),
        })
        .select()
        .single();

    // ========================================================
    // DATABASE ERROR
    // ========================================================

    if (userError) {

      console.error(
        "[DATABASE ERROR]",
        {
          message: userError.message,
          details: userError.details,
          hint: userError.hint,
          code: userError.code,
        }
      );

      // ======================================================
      // ROLLBACK AUTH USER
      // ======================================================

      console.log(
        "[ROLLBACK] Deleting Auth user:",
        authUser.id
      );

      const {
        error: deleteError,
      } =
        await supabaseAdmin.auth.admin.deleteUser(
          authUser.id
        );

      if (deleteError) {

        console.error(
          "[ROLLBACK ERROR]",
          {
            message: deleteError.message,
            status: deleteError.status,
          }
        );

      } else {

        console.log(
          "[ROLLBACK] Auth user deleted successfully"
        );
      }

      return Response.json(
        {
          success: false,
          error: userError.message,
        },
        {
          status: 500,
          headers: corsHeaders,
        }
      );
    }

    // ========================================================
    // SUCCESS
    // ========================================================

    console.log(
      "[DATABASE] public.jnv_users insert successful"
    );

    console.log(
      "[DATABASE] Internal User ID:",
      userData?.user_id
    );

    console.log(
      "[AUTH] Auth User ID:",
      authUser.id
    );

    console.log(
      "[SUCCESS] User registration completed"
    );

    // ========================================================
    // RESPONSE
    // ========================================================

    return Response.json(
      {
        success: true,

        message:
          "User registered successfully",

        user: userData,
      },
      {
        status: 201,
        headers: corsHeaders,
      }
    );

  } catch (error) {

    console.error(
      "================================================="
    );

    console.error(
      "[FATAL ERROR]",
      error
    );

    console.error(
      "================================================="
    );

    return Response.json(
      {
        success: false,

        error:
          error instanceof Error
            ? error.message
            : "Unknown error",
      },
      {
        status: 500,
        headers: corsHeaders,
      }
    );
  }
});
