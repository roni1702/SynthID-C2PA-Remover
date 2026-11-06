/**
 * SynthID Remover - Cloudflare Worker Engine (Unified Repository)
 * ডোমেন লক: https://mdroni1702.github.io
 * কঠোর ১ ডিভাইস = ১ অ্যাকাউন্ট এবং এসকিউএল ইনজেকশন-মুক্ত আর্কিটেকচার
 */

// ১. সিকিউরিটি কনফিগারেশন
const JWT_SECRET = "CF_SECURE_HMAC_SECRET_AUTH_KEY_2026";

// ২. অনুমোদিত ডোমেনের তালিকা (আপনার গিটহাব ইউজারনেম সেট করা হয়েছে)
const ALLOWED_ORIGINS = [
  "https://mdroni1702.github.io", // আপনার গিটহাব পেজেস ডোমেন
  "http://localhost:2435",        // লোকালহোস্টে টেস্ট করার জন্য
  "null"                          // সরাসরি ব্রাউজারে ফাইল ওপেন করলে
];

// SHA-256 পাসওয়ার্ড হ্যাশার
async function hashText(str) {
  const buffer = new TextEncoder().encode(str + JWT_SECRET);
  const hash = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// অথ টোকেন মেকার
async function generateToken(payload) {
  const enc = new TextEncoder();
  const data = JSON.stringify(payload);
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
  return btoa(data) + "." + sigHex;
}

// অথ টোকেন ভ্যালিডেটর
async function authenticate(request) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.split(" ")[1];
  const parts = token.split(".");
  if (parts.length !== 2) return null;

  try {
    const dataStr = atob(parts[0]);
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(JWT_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigBytes = new Uint8Array(parts[1].match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, enc.encode(dataStr));
    return valid ? JSON.parse(dataStr) : null;
  } catch (e) {
    return null;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method;

    // অরিজিন যাচাইকরণ (শুধুমাত্র আপনার গিটহাব পেজ রিকোয়েস্ট পাঠাতে পারবে)
    const requestOrigin = request.headers.get("Origin") || "";
    const isAllowed = ALLOWED_ORIGINS.includes(requestOrigin);

    if (requestOrigin && !isAllowed) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: "অননুমোদিত ডোমেন থেকে রিকোয়েস্ট প্রত্যাখ্যাত।" 
      }), {
        status: 403,
        headers: { "Content-Type": "application/json" }
      });
    }

    const corsHeaders = {
      "Access-Control-Allow-Origin": isAllowed ? requestOrigin : ALLOWED_ORIGINS[0],
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const respond = (data, status = 200) => {
      return new Response(JSON.stringify(data), {
        status,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    };

    try {
      // ১. সাইনআপ হ্যান্ডলার (কঠোর ১ ডিভাইস = ১ অ্যাকাউন্ট)
      if (url.pathname === "/api/auth/signup" && method === "POST") {
        const { username, password, fingerprint, referralCode } = await request.json();
        const cleanUser = (username || "").trim().toLowerCase();

        if (!cleanUser || !password || !fingerprint) {
          return respond({ success: false, message: "সকল প্রয়োজনীয় তথ্য পূরণ করুন।" }, 400);
        }

        // ইউজারনেম ডুপ্লিকেট চেক
        const existingUser = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(cleanUser).first();
        if (existingUser) {
          return respond({ success: false, message: "এই ইউজারনেমটি ইতিমধ্যে নেওয়া হয়েছে।" }, 400);
        }

        // ডিভাইস ভেরিফিকেশন (একই ডিভাইস থেকে দ্বিতীয় একাউন্ট ব্লক)
        const fpCheck = await env.DB.prepare("SELECT id FROM device_fingerprints WHERE fingerprint = ?").bind(fingerprint).first();
        if (fpCheck) {
          return respond({ 
            success: false, 
            message: "এই ডিভাইস থেকে ইতিপূর্বে একটি অ্যাকাউন্ট তৈরি করা হয়েছে। একই ডিভাইস থেকে একাধিক অ্যাকাউন্ট তৈরি করার অনুমতি নেই।" 
          }, 403);
        }

        // রেফারেল চেক
        let referrerId = null;
        if (referralCode) {
          const refUser = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(referralCode.trim().toLowerCase()).first();
          if (refUser) {
            referrerId = refUser.id;
          }
        }

        const hashedPass = await hashText(password);
        const userInsert = await env.DB.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id")
          .bind(cleanUser, hashedPass)
          .first();

        const newUserId = userInsert.id;

        // ৫ স্টার প্রাথমিক ব্যালেন্স দেওয়া
        await env.DB.prepare("INSERT INTO balances (user_id, stars, is_unlimited) VALUES (?, 5, 0)").bind(newUserId).run();
        
        // ডিভাইস ফিঙ্গারপ্রিন্ট লক করা
        await env.DB.prepare("INSERT INTO device_fingerprints (fingerprint, user_id) VALUES (?, ?)").bind(fingerprint, newUserId).run();

        // রেফারকারীকে ৫ স্টার বোনাস দেওয়া
        if (referrerId) {
          await env.DB.prepare("UPDATE balances SET stars = stars + 5 WHERE user_id = ?").bind(referrerId).run();
        }

        const token = await generateToken({ id: newUserId, username: cleanUser, role: "user" });
        return respond({ success: true, token, message: "অ্যাকাউন্ট সফলভাবে তৈরি হয়েছে।" });
      }

      // ২. লগইন হ্যান্ডলার
      if (url.pathname === "/api/auth/login" && method === "POST") {
        const { username, password } = await request.json();
        const cleanUser = (username || "").trim().toLowerCase();

        const user = await env.DB.prepare("SELECT id, username, password_hash, role FROM users WHERE username = ?").bind(cleanUser).first();
        if (!user) {
          return respond({ success: false, message: "ইউজারনেম অথবা পাসওয়ার্ড সঠিক নয়।" }, 400);
        }

        const checkHash = await hashText(password);
        if (user.password_hash !== checkHash) {
          return respond({ success: false, message: "ইউজারনেম অথবা পাসওয়ার্ড সঠিক নয়।" }, 400);
        }

        const token = await generateToken({ id: user.id, username: user.username, role: user.role });
        return respond({ success: true, token, role: user.role, message: "লগইন সফল হয়েছে।" });
      }

      // প্রোটেক্টেড রুট গার্ড
      const auth = await authenticate(request);
      if (!auth) {
        return respond({ success: false, message: "অননুমোদিত সেশন।" }, 401);
      }

      // ৩. ইউজার স্টেটাস ও ব্যালেন্স সিঙ্ক
      if (url.pathname === "/api/user/status" && method === "GET") {
        const row = await env.DB.prepare("SELECT stars, is_unlimited, last_daily_claim FROM balances WHERE user_id = ?").bind(auth.id).first();
        return respond({
          success: true,
          username: auth.username,
          role: auth.role,
          stars: row ? row.stars : 0,
          isUnlimited: row ? Boolean(row.is_unlimited) : false,
          lastDailyClaim: row ? row.last_daily_claim : null
        });
      }

      // ৪. ডেইলি ফ্রি ক্লেম
      if (url.pathname === "/api/user/claim-daily" && method === "POST") {
        const today = new Date().toISOString().slice(0, 10);
        const row = await env.DB.prepare("SELECT last_daily_claim FROM balances WHERE user_id = ?").bind(auth.id).first();

        if (row && row.last_daily_claim === today) {
          return respond({ success: false, message: "আজকের ফ্রি স্টার ইতিমধ্যে ক্লেইম করা হয়েছে।" }, 400);
        }

        await env.DB.prepare("UPDATE balances SET stars = stars + 1, last_daily_claim = ? WHERE user_id = ?").bind(today, auth.id).run();
        return respond({ success: true, message: "১টি ফ্রি স্টার আপনার অ্যাকাউন্টে যোগ করা হয়েছে।" });
      }

      // ৫. ছবি প্রসেসের জন্য স্টার ডিডাক্ট
      if (url.pathname === "/api/user/deduct-star" && method === "POST") {
        const balance = await env.DB.prepare("SELECT stars, is_unlimited FROM balances WHERE user_id = ?").bind(auth.id).first();
        if (!balance) return respond({ success: false, message: "ব্যালেন্স পাওয়া যায়নি।" }, 404);

        if (balance.is_unlimited === 1) {
          return respond({ success: true, remaining: "Unlimited" });
        }

        if (balance.stars <= 0) {
          return respond({ success: false, message: "পর্যাপ্ত ব্যালেন্স নেই। দয়া করে প্যাকেজ কিনুন।" }, 403);
        }

        await env.DB.prepare("UPDATE balances SET stars = stars - 1 WHERE user_id = ?").bind(auth.id).run();
        return respond({ success: true, remaining: balance.stars - 1 });
      }

      // ৬. পেমেন্ট সাবমিশন
      if (url.pathname === "/api/payment/submit" && method === "POST") {
        const { planId, amount, senderNumber, trxId } = await request.json();
        const cleanTrx = (trxId || "").trim().toUpperCase();

        if (!planId || !amount || !senderNumber || !cleanTrx) {
          return respond({ success: false, message: "সবগুলো ফিল্ড সঠিকভাবে পূরণ করুন।" }, 400);
        }

        try {
          await env.DB.prepare("INSERT INTO transactions (user_id, plan_id, amount, sender_number, trx_id) VALUES (?, ?, ?, ?, ?)")
            .bind(auth.id, planId, amount, senderNumber.trim(), cleanTrx)
            .run();
          return respond({ success: true, message: "পেমেন্ট তথ্য গৃহীত হয়েছে। এডমিন যাচাই করে দ্রুত স্টার যুক্ত করবে।" });
        } catch (e) {
          return respond({ success: false, message: "এই ট্রানজেকশন আইডি ইতিপূর্বে সাবমিট করা হয়েছে।" }, 400);
        }
      }

      // ৭. এডমিন রাউটস
      if (url.pathname.startsWith("/api/admin/")) {
        const checkRole = await env.DB.prepare("SELECT role FROM users WHERE id = ?").bind(auth.id).first();
        if (!checkRole || checkRole.role !== "admin") {
          return respond({ success: false, message: "এডমিন অনুমতি নেই।" }, 403);
        }

        if (url.pathname === "/api/admin/transactions" && method === "GET") {
          const { results } = await env.DB.prepare(`
            SELECT t.id, t.user_id, t.plan_id, t.amount, t.sender_number, t.trx_id, t.status, t.created_at, u.username
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            ORDER BY t.id DESC LIMIT 100
          `).all();
          return respond({ success: true, transactions: results });
        }

        if (url.pathname === "/api/admin/action" && method === "POST") {
          const { trxId, action } = await request.json();
          const target = await env.DB.prepare("SELECT * FROM transactions WHERE id = ?").bind(trxId).first();

          if (!target || target.status !== "pending") {
            return respond({ success: false, message: "অনুরোধটি অবৈধ অথবা ইতিমধ্যে সমাধানকৃত।" }, 400);
          }

          if (action === "approve") {
            if (target.plan_id === "p1") {
              await env.DB.prepare("UPDATE balances SET stars = stars + 10 WHERE user_id = ?").bind(target.user_id).run();
            } else if (target.plan_id === "p2") {
              await env.DB.prepare("UPDATE balances SET stars = stars + 30 WHERE user_id = ?").bind(target.user_id).run();
            } else if (target.plan_id === "p3") {
              await env.DB.prepare("UPDATE balances SET is_unlimited = 1 WHERE user_id = ?").bind(target.user_id).run();
            }
            await env.DB.prepare("UPDATE transactions SET status = 'approved' WHERE id = ?").bind(trxId).run();
          } else {
            await env.DB.prepare("UPDATE transactions SET status = 'rejected' WHERE id = ?").bind(trxId).run();
          }

          return respond({ success: true, message: "অ্যাকশন সফলভাবে কার্যকর হয়েছে।" });
        }
      }

      return respond({ success: false, message: "এন্ডপয়েন্ট পাওয়া যায়নি।" }, 404);

    } catch (err) {
      return respond({ success: false, message: "সার্ভার এরর: " + err.message }, 500);
    }
  }
};
