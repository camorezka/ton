// =====================================================================
// api/bot.js — Vercel Serverless Function
// Telegram webhook + Mini App launcher + TON on-chain memo verification
// for a fantasy crypto collectible card game (cosmetic NFT-style items —
// no real payment-card data involved).
//
// Required Vercel Environment Variables:
//   BOT_TOKEN            - Telegram bot token from @BotFather
//   APP_URL               - e.g. https://your-app.vercel.app
//   SUPABASE_URL          - Supabase project URL
//   SUPABASE_SERVICE_KEY  - Supabase service role key
//   TONAPI_KEY            - (optional) TonAPI.io bearer token, raises rate limits
//   SERVICE_WALLET         - platform TON wallet address (receives payments)
//
// Security notes:
//   - Every mutating action (create_order, charge_complete, verify) requires
//     a verified Telegram `initData` sent as `Authorization: Bearer <initData>`.
//   - Never trust telegram_id / user identity coming from req.body directly.
//   - Optionally wire POST /api/bot?action=cleanup_expired to Vercel Cron
//     (vercel.json -> "crons": [{ "path": "/api/bot?action=cleanup_expired",
//     "schedule": "*/5 * * * *" }]) to sweep stale locks even when nobody
//     is actively polling.
// =====================================================================

import crypto from "node:crypto";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const BOT_TOKEN = process.env.BOT_TOKEN;
const APP_URL = process.env.APP_URL || "https://your-app.vercel.app";
const SERVICE_WALLET = process.env.SERVICE_WALLET || "";
const TONAPI_KEY = process.env.TONAPI_KEY || "";

// ---------------------------------------------------------------------
// tiny Supabase REST helper (no SDK needed -> zero cold-start bloat)
// ---------------------------------------------------------------------
async function sb(path, opts = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...opts,
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      "Content-Type": "application/json",
      Prefer: opts.prefer || "return=representation",
      ...(opts.headers || {}),
    },
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Supabase error ${res.status}: ${t}`);
  }
  return res.status === 204 ? null : res.json();
}

// ---------------------------------------------------------------------
// Telegram API helper
// NOTE: fetch() does NOT throw on non-2xx / { ok:false } responses, so
// without this explicit check a failed sendMessage (bad token, invalid
// web_app URL, bad parse_mode, etc.) would silently do nothing while the
// serverless function still returns 200 to Telegram's webhook delivery.
// Always check the logs for "Telegram API error" after a suspected
// "bot doesn't respond" issue.
// ---------------------------------------------------------------------
async function tg(method, payload) {
  const res = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!data.ok) {
    console.error(`Telegram API error on ${method}:`, data.description, data);
  }
  return data;
}

// ---------------------------------------------------------------------
// TonAPI: fetch recent incoming transactions to SERVICE_WALLET and look
// for one whose comment == memo and amount (in TON) >= expected.
// ---------------------------------------------------------------------
async function findTonTransaction(memo, expectedAmountTon) {
  if (!SERVICE_WALLET) throw new Error("SERVICE_WALLET not configured");

  const url = `https://tonapi.io/v2/blockchain/accounts/${SERVICE_WALLET}/transactions?limit=50`;
  const res = await fetch(url, {
    headers: TONAPI_KEY ? { Authorization: `Bearer ${TONAPI_KEY}` } : {},
  });
  if (!res.ok) throw new Error(`TonAPI error ${res.status}`);
  const data = await res.json();

  const expectedNano = BigInt(Math.round(expectedAmountTon * 1e9));

  for (const tx of data.transactions || []) {
    const inMsg = tx.in_msg;
    if (!inMsg) continue;

    const comment =
      inMsg.decoded_body?.text ||
      inMsg.decoded_op_name === "text_comment"
        ? inMsg.decoded_body?.text
        : null;

    const rawComment = comment || extractCommentFallback(inMsg);
    const amountNano = BigInt(inMsg.value || 0);

    if (rawComment && rawComment.trim() === memo && amountNano >= expectedNano) {
      return { txHash: tx.hash, amountNano: amountNano.toString() };
    }
  }
  return null;
}

function extractCommentFallback(inMsg) {
  try {
    return inMsg?.decoded_body?.text || null;
  } catch {
    return null;
  }
}

// =====================================================================
// (1) SECURITY: Telegram WebApp initData verification (HMAC-SHA256)
// =====================================================================
// Telegram signs `initData` with a secret derived from the bot token.
// We MUST verify this signature server-side before trusting ANY user
// identity coming from the client — otherwise anyone can POST
// { telegram_id: <victim's id> } and act as another user (spoofing).
//
// Algorithm (per Telegram docs):
//   secret_key   = HMAC_SHA256("WebAppData", BOT_TOKEN)
//   data_check_string = all initData fields (except `hash`), sorted
//                        alphabetically, joined as "key=value" with "\n"
//   computed_hash = HMAC_SHA256(secret_key, data_check_string) as hex
//   valid if computed_hash === hash (constant-time compare)
// =====================================================================
const MAX_INITDATA_AGE_SEC = 24 * 60 * 60; // 24h — reject stale sessions

function verifyInitData(initData) {
  if (!initData || typeof initData !== "string") return null;
  if (!BOT_TOKEN) throw new Error("BOT_TOKEN not configured");

  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return null;
  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const secretKey = crypto.createHmac("sha256", "WebAppData").update(BOT_TOKEN).digest();
  const computedHash = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");

  const a = Buffer.from(computedHash, "hex");
  const b = Buffer.from(hash, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  const authDate = Number(params.get("auth_date") || 0);
  if (!authDate || Date.now() / 1000 - authDate > MAX_INITDATA_AGE_SEC) return null; // expired session

  const userRaw = params.get("user");
  if (!userRaw) return null;

  try {
    return JSON.parse(userRaw); // { id, username, first_name, ... }
  } catch {
    return null;
  }
}

// Extracts and verifies the calling user from Authorization header
// ("Bearer <initData>") or, as a fallback, req.body.initData.
// Returns the verified Telegram user object, or null if invalid.
function getVerifiedUser(req) {
  const authHeader = req.headers?.authorization || req.headers?.Authorization || "";
  const bearerInitData = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  const initData = bearerInitData || req.body?.initData;
  return verifyInitData(initData);
}

// =====================================================================
// (2) BUSINESS LOGIC: auto-expire stale pending orders & unlock cards
// =====================================================================
// Calls the atomic Postgres function `cleanup_expired_orders()`
// (see schema.sql) which, in a single transaction:
//   - flips any `orders` row stuck in `pending` for > 15 minutes to `expired`
//   - unlocks (`is_locked = false`) the cards tied to those orders
// This prevents a buyer from permanently soft-locking a card by opening
// the buy sheet and never paying (or paying to the wrong memo).
async function cleanupExpiredOrders() {
  try {
    const result = await sb("rpc/cleanup_expired_orders", {
      method: "POST",
      body: JSON.stringify({}),
    });
    return { cleaned: result ?? 0 };
  } catch (e) {
    console.error("cleanupExpiredOrders failed:", e.message);
    return { cleaned: 0, error: e.message };
  }
}

// ---------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------
export default async function handler(req, res) {
  try {
    // -------------------------------------------------------------
    // POST /api/bot  -> could be Telegram webhook OR internal action
    // Distinguish via req.body shape / query param `action`
    // -------------------------------------------------------------
    const { action } = req.query;

    // ---- 0) MANUAL / CRON CLEANUP ----------------------------------
    // POST /api/bot?action=cleanup_expired
    // Wire this to a Vercel Cron (e.g. every 5 min) in vercel.json, or
    // it is called automatically before verify/create_order below.
    if (action === "cleanup_expired" && req.method === "POST") {
      const result = await cleanupExpiredOrders();
      return res.status(200).json({ ok: true, ...result });
    }

    // ---- 1) TRANSACTION VERIFICATION ENDPOINT --------------------
    // POST /api/bot?action=verify   { memo }
    // Header: Authorization: Bearer <telegram_initData>
    if (action === "verify" && req.method === "POST") {
      const verifiedUser = getVerifiedUser(req);
      if (!verifiedUser) {
        return res.status(401).json({ ok: false, error: "invalid or missing initData" });
      }

      await cleanupExpiredOrders(); // sweep stale locks before checking this one

      const { memo } = req.body || {};
      if (!memo) return res.status(400).json({ ok: false, error: "memo required" });

      const orders = await sb(
        `orders?deal_memo=eq.${encodeURIComponent(memo)}&status=eq.pending&select=*`
      );
      const order = orders?.[0];
      if (!order) {
        return res.status(404).json({ ok: false, error: "order not found, expired or already processed" });
      }

      // Only the buyer who created the order may poll/confirm it
      const buyers = await sb(`users?telegram_id=eq.${verifiedUser.id}&select=id`);
      if (!buyers?.[0] || buyers[0].id !== order.buyer_id) {
        return res.status(403).json({ ok: false, error: "not your order" });
      }

      const found = await findTonTransaction(memo, Number(order.amount_ton));
      if (!found) {
        return res.status(200).json({ ok: true, confirmed: false });
      }

      // Atomic settlement: call Postgres function confirm_order(memo, tx_hash)
      await sb("rpc/confirm_order", {
        method: "POST",
        body: JSON.stringify({ p_memo: memo, p_tx_hash: found.txHash }),
      });

      return res.status(200).json({ ok: true, confirmed: true, tx_hash: found.txHash });
    }

    // ---- 2) CREATE ORDER (generates unique memo) ------------------
    // POST /api/bot?action=create_order  { auction_id }
    // Header: Authorization: Bearer <telegram_initData>
    // NOTE: buyer identity comes ONLY from the verified initData now —
    // `buyer_telegram_id` is no longer accepted from the request body,
    // which previously let anyone place an order "as" another user.
    if (action === "create_order" && req.method === "POST") {
      const verifiedUser = getVerifiedUser(req);
      if (!verifiedUser) {
        return res.status(401).json({ ok: false, error: "invalid or missing initData" });
      }

      await cleanupExpiredOrders(); // free up any stale locks first

      const { auction_id } = req.body || {};
      if (!auction_id) {
        return res.status(400).json({ ok: false, error: "auction_id required" });
      }

      const auctions = await sb(`auctions?id=eq.${auction_id}&select=*`);
      const auction = auctions?.[0];
      if (!auction || auction.status !== "active") {
        return res.status(404).json({ ok: false, error: "auction not active" });
      }

      const itemCheck = await sb(`collectibles?id=eq.${auction.item_id}&select=is_locked`);
      if (itemCheck?.[0]?.is_locked) {
        return res.status(409).json({ ok: false, error: "item already locked in another pending order" });
      }

      const buyers = await sb(`users?telegram_id=eq.${verifiedUser.id}&select=*`);
      const buyer = buyers?.[0];
      if (!buyer) return res.status(404).json({ ok: false, error: "buyer not found" });

      if (buyer.id === auction.seller_id) {
        return res.status(400).json({ ok: false, error: "cannot buy your own listing" });
      }

      // lock the item
      await sb(`collectibles?id=eq.${auction.item_id}`, {
        method: "PATCH",
        body: JSON.stringify({ is_locked: true }),
      });

      const memo = `deal_${auction.id.slice(0, 8)}_${Math.random().toString(36).slice(2, 7)}`;

      const orderRows = await sb("orders", {
        method: "POST",
        body: JSON.stringify({
          deal_memo: memo,
          auction_id: auction.id,
          item_id: auction.item_id,
          buyer_id: buyer.id,
          seller_id: auction.seller_id,
          amount_ton: auction.price_ton,
          service_wallet: SERVICE_WALLET,
          status: "pending",
        }),
      });

      return res.status(200).json({
        ok: true,
        order: orderRows[0],
        pay_to: SERVICE_WALLET,
        memo,
        amount_ton: auction.price_ton,
      });
    }

    // ---- 3) SHAKE-TO-CHARGE reward ---------------------------------
    // POST /api/bot?action=charge_complete { item_id }
    // Header: Authorization: Bearer <telegram_initData>
    // `telegram_id` is taken from the verified initData, not the body,
    // so a client can no longer farm streak/charge rewards for another user.
    if (action === "charge_complete" && req.method === "POST") {
      const verifiedUser = getVerifiedUser(req);
      if (!verifiedUser) {
        return res.status(401).json({ ok: false, error: "invalid or missing initData" });
      }

      const { item_id } = req.body || {};
      const telegram_id = verifiedUser.id;

      const users = await sb(`users?telegram_id=eq.${telegram_id}&select=*`);
      const user = users?.[0];
      if (!user) return res.status(404).json({ ok: false, error: "user not found" });

      // Only the item's owner can charge it
      const itemCheck = await sb(`collectibles?id=eq.${item_id}&select=owner_id`);
      if (!itemCheck?.[0] || itemCheck[0].owner_id !== user.id) {
        return res.status(403).json({ ok: false, error: "you do not own this item" });
      }

      await sb(`collectibles?id=eq.${item_id}`, {
        method: "PATCH",
        body: JSON.stringify({ is_charged: true, charge_progress: 100 }),
      });

      const now = new Date();
      const last = user.last_shake_at ? new Date(user.last_shake_at) : null;
      const isNewDay = !last || now.toDateString() !== last.toDateString();
      const newStreak = isNewDay ? (user.daily_streak || 0) + 1 : user.daily_streak;

      await sb(`users?telegram_id=eq.${telegram_id}`, {
        method: "PATCH",
        body: JSON.stringify({ daily_streak: newStreak, last_shake_at: now.toISOString() }),
      });

      return res.status(200).json({ ok: true, daily_streak: newStreak });
    }

    // ---- SUPPORT MESSAGE -------------------------------------------
    if (action === "support_message" && req.method === "POST") {
      const verifiedUser = getVerifiedUser(req);
      if (!verifiedUser) return res.status(401).json({ ok:false, error:"invalid or missing initData" });
      const message = String(req.body?.message || "").trim().slice(0, 2000);
      if (!message) return res.status(400).json({ ok:false, error:"Введите сообщение" });

      await sb("support_messages", {
        method: "POST",
        body: JSON.stringify({
          telegram_id: verifiedUser.id,
          username: verifiedUser.username || null,
          first_name: verifiedUser.first_name || null,
          message
        })
      });

      const text = [
        "🆘 Поддержка Cards Auction",
        "",
        "Telegram ID: " + verifiedUser.id,
        "Username: @" + (verifiedUser.username || "нет"),
        "Имя: " + (verifiedUser.first_name || "Пользователь"),
        "",
        message
      ].join("\n");

      if (process.env.SUPPORT_CHAT_ID) {
        const sent = await tg("sendMessage", {
          chat_id: process.env.SUPPORT_CHAT_ID,
          text
        });
        if (!sent?.ok) console.error("Support Telegram delivery failed:", sent.description);
      }

      return res.status(200).json({ ok:true });
    }

    // ---- 3a) CREATE VIRTUAL COLLECTIBLE CARD ------------------------
    if (action === "create_card" && req.method === "POST") {
      const verifiedUser = getVerifiedUser(req);
      if (!verifiedUser) return res.status(401).json({ ok: false, error: "invalid or missing initData" });

      const users = await sb(`users?telegram_id=eq.${verifiedUser.id}&select=id`);
      const user = users?.[0];
      if (!user) return res.status(404).json({ ok: false, error: "user not found" });

      const requested = String(req.body?.serial_code || "").replace(/\D/g, "").slice(0, 4);
      const skinId = String(req.body?.skin_id || "photo_1").slice(0, 80);
      const title = String(req.body?.title || "Без названия").trim().slice(0, 60) || "Без названия";
      const description = String(req.body?.description || "").trim().slice(0, 300) || null;
      const visibility = req.body?.visibility === "private" ? "private" : "public";
      if (!/^\d{4}$/.test(requested)) return res.status(400).json({ ok: false, error: "Введите ровно 4 цифры" });

      const existing = await sb(`collectibles?serial_code=eq.${encodeURIComponent(requested)}&select=id&limit=1`);
      if (existing?.[0]) return res.status(409).json({ ok: false, error: "Этот номер уже используется" });

      const password = String(req.body?.card_password || "").replace(/\D/g, "").slice(0, 6) || String(Math.floor(Math.random() * 1000000)).padStart(6, "0");
      const accessKey = crypto.randomUUID();
      const rows = await sb("collectibles", {
        method: "POST",
        body: JSON.stringify({ owner_id: user.id, serial_code: requested, access_key: accessKey, card_password: password, skin_id: skinId, wallet_address: null, title, description, visibility })
      });
      return res.status(200).json({ ok: true, card: rows?.[0] || null });
    }

    // ---- 3b) LOAD CURRENT CARD -------------------------------------
    if (action === "get_my_card" && req.method === "POST") {
      const verifiedUser = getVerifiedUser(req);
      if (!verifiedUser) return res.status(401).json({ ok: false, error: "invalid or missing initData" });

      const users = await sb(`users?telegram_id=eq.${verifiedUser.id}&select=id`);
      const user = users?.[0];
      if (!user) return res.status(404).json({ ok: false, error: "user not found" });

      const cards = await sb(`collectibles?owner_id=eq.${user.id}&select=id,serial_code,skin_id,card_password,wallet_address,title,description,visibility,transfer_count,created_at&order=created_at.asc`);
      return res.status(200).json({ ok: true, card: cards?.[0] || null });
    }

    // ---- 3c) CHECK 4-DIGIT CARD NUMBER -----------------------------
    if (action === "check_card_number" && req.method === "POST") {
      const verifiedUser = getVerifiedUser(req);
      if (!verifiedUser) return res.status(401).json({ ok: false, error: "invalid or missing initData" });

      const { card_number, item_id } = req.body || {};
      const value = String(card_number || "");
      if (!/^\d{4}$/.test(value)) {
        return res.status(400).json({ ok: false, available: false, error: "Номер должен содержать ровно 4 цифры" });
      }

      const existing = await sb(`collectibles?serial_code=eq.${encodeURIComponent(value)}&select=id&limit=1`);
      if (existing?.[0] && String(existing[0].id) !== String(item_id || "")) {
        return res.status(200).json({ ok: true, available: false, error: "Этот номер уже используется" });
      }

      return res.status(200).json({ ok: true, available: true });
    }

    // ---- 3b) UPDATE COLLECTIBLE COSMETICS (serial code + skin) -----
    // POST /api/bot?action=update_card_settings { item_id, serial_code, skin_id }
    // Header: Authorization: Bearer <telegram_initData>
    // Cosmetic-only fields: an 8-digit player-chosen serial code and a
    // skin preset id. Validated server-side; owner-only.
    if (action === "update_card_settings" && req.method === "POST") {
      const verifiedUser = getVerifiedUser(req);
      if (!verifiedUser) {
        return res.status(401).json({ ok: false, error: "invalid or missing initData" });
      }

      const { item_id, serial_code, card_password, skin_id, wallet_address, title, description, visibility } = req.body || {};
      if (serial_code && !/^\d{4}$/.test(String(serial_code))) {
        return res.status(400).json({ ok: false, error: "serial_code must be exactly 4 digits" });
      }
      if (serial_code) {
        const duplicate = await sb(`collectibles?serial_code=eq.${encodeURIComponent(String(serial_code))}&select=id&limit=1`);
        if (duplicate?.[0] && String(duplicate[0].id) !== String(item_id || "")) {
          return res.status(409).json({ ok: false, error: "Этот номер уже используется" });
        }
      }

      const users = await sb(`users?telegram_id=eq.${verifiedUser.id}&select=id`);
      const user = users?.[0];
      if (!user) return res.status(404).json({ ok: false, error: "user not found" });

      const patch = {};
      if (serial_code) patch.serial_code = String(serial_code);
      if (card_password !== undefined) {
        const cp = String(card_password).replace(/\D/g, '').slice(0,6);
        if (!/^\d{6}$/.test(cp)) return res.status(400).json({ ok:false, error:'Код карты должен содержать 6 цифр' });
        patch.card_password = cp;
      }
      if (skin_id) patch.skin_id = String(skin_id);
      if (wallet_address !== undefined) patch.wallet_address = wallet_address ? String(wallet_address) : null;
      if (title !== undefined) patch.title = String(title).trim().slice(0,60) || 'Без названия';
      if (description !== undefined) patch.description = String(description).trim().slice(0,300) || null;
      if (visibility !== undefined) patch.visibility = visibility === 'private' ? 'private' : 'public';

      if (item_id) {
        // Updating a specific owned collectible
        const itemCheck = await sb(`collectibles?id=eq.${item_id}&select=owner_id`);
        if (!itemCheck?.[0] || itemCheck[0].owner_id !== user.id) {
          return res.status(403).json({ ok: false, error: "you do not own this item" });
        }
        await sb(`collectibles?id=eq.${item_id}`, { method: "PATCH", body: JSON.stringify(patch) });
      } else {
        // No item_id supplied (e.g. demo/local card) — just acknowledge,
        // nothing to persist server-side.
        return res.status(200).json({ ok: true, persisted: false });
      }

      return res.status(200).json({ ok: true, persisted: true });
    }

    // ---- 4) TELEGRAM WEBHOOK ---------------------------------------
    if (req.method === "POST") {
      const update = req.body;
      const msg = update.message;

      // TEMP DEBUG LOGGING — remove once the "bot doesn't reply" issue
      // is confirmed fixed. Logs unconditionally (not just on error) so
      // we can see in Vercel Logs exactly what update arrived and what
      // Telegram said back, without needing to expand any UI panel.
      console.log("Incoming update:", JSON.stringify(update));

      // NOTE: was `msg.text === "/start"` — that fails to match deep-link
      // starts like "/start ref_xxxx" or "/start@YourBotName" in groups.
      // startsWith() is the more forgiving, standard way to detect the
      // /start command.
      if (msg && msg.text && msg.text.startsWith("/start")) {
        console.log("Matched /start from", msg.from.id, msg.from.username);

        // upsert user
        await sb("users", {
          method: "POST",
          prefer: "resolution=merge-duplicates,return=representation",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            telegram_id: msg.from.id,
            username: msg.from.username || null,
            first_name: msg.from.first_name || null,
          }),
        }).catch((e) => {
          console.error("users upsert failed:", e.message); // was: silently swallowed
        });

        const sendResult = await tg("sendMessage", {
          chat_id: msg.chat.id,
          text:
            "💳 *Card Vault* — collect, charge & trade rare bank cards on TON.\n\n" +
            "Tap below to open the vault.",
          parse_mode: "Markdown",
          reply_markup: {
            inline_keyboard: [[{ text: "🚀 Open Card Vault", web_app: { url: APP_URL } }]],
          },
        });
        console.log("sendMessage result:", JSON.stringify(sendResult));
      } else {
        console.log("No /start match. msg.text was:", msg?.text);
      }

      return res.status(200).json({ ok: true });
    }

    // ---- default ----------------------------------------------------
    return res.status(200).json({ ok: true, service: "card-vault-bot", status: "alive" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: err.message });
  }
}
