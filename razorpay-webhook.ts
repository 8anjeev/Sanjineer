// ================================================================
// Sanjineer — Razorpay Webhook Handler
// Deploy as: Supabase Edge Function named "razorpay-webhook"
// ================================================================

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { hmac } from "https://deno.land/x/hmac@v2.0.1/mod.ts";

const RAZORPAY_WEBHOOK_SECRET = Deno.env.get("RAZORPAY_WEBHOOK_SECRET")!;
const SUPABASE_URL            = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_KEY    = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

serve(async (req: Request) => {
  // Only accept POST
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const body      = await req.text();
  const signature = req.headers.get("x-razorpay-signature") ?? "";

  // ── 1. Verify signature ──────────────────────────────────────
  const expectedSig = hmac("sha256", RAZORPAY_WEBHOOK_SECRET, body, "utf8", "hex");
  if (expectedSig !== signature) {
    console.error("Invalid webhook signature");
    return new Response("Unauthorized", { status: 401 });
  }

  const event = JSON.parse(body);
  console.log("Webhook event:", event.event);

  // ── 2. Only handle payment.captured ─────────────────────────
  if (event.event !== "payment.captured") {
    return new Response("OK", { status: 200 });
  }

  const payment  = event.payload?.payment?.entity;
  const payId    = payment?.id;
  const email    = payment?.email ?? payment?.notes?.email ?? "";
  const amount   = payment?.amount ?? 0;   // in paise
  const purpose  = payment?.notes?.purpose ?? "";

  if (!email || purpose !== "sanjineer_cloud_subscription") {
    console.log("Skipping — not a subscription payment");
    return new Response("OK", { status: 200 });
  }

  // ── 3. Write to Supabase using service role (bypasses RLS) ───
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

  // Find admin by email
  const { data: authUser } = await sb.auth.admin.listUsers();
  const user = authUser?.users?.find((u: any) => u.email === email);

  if (!user) {
    console.error("No Supabase user found for email:", email);
    // Still log the payment even if user not found yet
    await sb.from("payments").insert({
      razorpay_id: payId,
      amount:      Math.round(amount / 100),
      purpose:     "sanjineer_cloud_subscription",
      admin_id:    null,
    }).catch(() => {});
    return new Response("OK", { status: 200 });
  }

  const subEnd = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days

  // Upsert admin row
  const { error: adminErr } = await sb.from("admins").upsert({
    id:                    user.id,
    email:                 email,
    subscribed:            true,
    subscribed_at:         Date.now(),
    subscription_end_date: subEnd,
    last_payment_id:       payId,
  }, { onConflict: "id" });

  if (adminErr) {
    console.error("Admin upsert error:", adminErr);
    return new Response("DB Error", { status: 500 });
  }

  // Log payment
  await sb.from("payments").insert({
    admin_id:    user.id,
    razorpay_id: payId,
    amount:      Math.round(amount / 100),
    purpose:     "sanjineer_cloud_subscription",
  }).catch(() => {});

  console.log(`✅ Subscription activated for ${email} until ${new Date(subEnd).toISOString()}`);
  return new Response("OK", { status: 200 });
});
