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
const AUCTION_COMMISSION_TON = 0.2;
const MIN_AUCTION_PRICE_TON = 3;
const ADMIN_TELEGRAM_ID = 1693493298;

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
const MAX_INITDATA_AGE_SEC = 10 * 60; // 10 minutes — reject stale sessions

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

    if (action === "icon" && req.method === "GET") {
      // 1x1 transparent PNG fallback; manifest only needs a valid PNG URL.
      const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64");
      res.statusCode = 200;
      res.setHeader("Content-Type", "image/png");
      res.setHeader("Cache-Control", "public, max-age=86400, immutable");
      return res.end(png);
    }

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

      const found = await findTonTransaction(memo, Number(order.commission_ton ?? AUCTION_COMMISSION_TON));
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

    // ---- PUBLIC CARD SEARCH / DETAILS -----------------------------
    if (action === "search_cards" && req.method === "POST") {
      const q = String(req.body?.query || "").replace(/\D/g, "").slice(0, 4);
      if (!q) return res.status(200).json({ ok: true, cards: [] });
      const cards = await sb(`collectibles?serial_code=ilike.${encodeURIComponent(q + "%")}&visibility=eq.public&select=id,serial_code,skin_id,title,description,transfer_count,created_at&order=created_at.desc&limit=30`);
      return res.status(200).json({ ok: true, cards: cards || [] });
    }

    if (action === "get_card_public" && req.method === "POST") {
      const itemId = String(req.body?.item_id || "");
      if (!itemId) return res.status(400).json({ ok:false, error:"item_id required" });
      const cards = await sb(`collectibles?id=eq.${encodeURIComponent(itemId)}&visibility=eq.public&select=id,serial_code,skin_id,title,description,transfer_count,created_at`);
      if (!cards?.[0]) return res.status(404).json({ ok:false, error:"card not found" });
      return res.status(200).json({ ok:true, card:cards[0] });
    }

    // ---- ACTIVE AUCTIONS ------------------------------------------
    if (action === "list_auctions" && req.method === "POST") {
      const rows = await sb(`auctions?status=eq.active&select=id,item_id,seller_id,price_ton,commission_ton,created_at,collectibles!inner(id,serial_code,skin_id,title,description,visibility)&order=created_at.desc&limit=50`);
      return res.status(200).json({ ok:true, auctions: rows || [] });
    }

    // ---- CREATE AUCTION -------------------------------------------
    if (action === "create_auction" && req.method === "POST") {
      const verifiedUser = getVerifiedUser(req);
      if (!verifiedUser) return res.status(401).json({ ok:false, error:"invalid or missing initData" });
      const users = await sb(`users?telegram_id=eq.${verifiedUser.id}&select=id`);
      const user = users?.[0];
      if (!user) return res.status(404).json({ ok:false, error:"user not found" });
      const itemId = String(req.body?.item_id || "");
      const price = Number(req.body?.price_ton);
      if (!itemId || !Number.isFinite(price) || price < MIN_AUCTION_PRICE_TON) {
        return res.status(400).json({ ok:false, error:`Минимальная ставка — ${MIN_AUCTION_PRICE_TON} TON` });
      }
      const items = await sb(`collectibles?id=eq.${encodeURIComponent(itemId)}&select=id,owner_id,is_locked,wallet_address,visibility`);
      const item = items?.[0];
      if (!item || String(item.owner_id) !== String(user.id)) return res.status(403).json({ok:false,error:"you do not own this card"});
      if (item.is_locked) return res.status(409).json({ok:false,error:"card is locked"});
      if (!item.wallet_address) return res.status(400).json({ok:false,error:"Привяжите TON-кошелёк к карточке"});
      const active = await sb(`auctions?item_id=eq.${encodeURIComponent(itemId)}&status=eq.active&select=id&limit=1`);
      if (active?.[0]) return res.status(409).json({ok:false,error:"Карточка уже выставлена"});
      const rows = await sb("auctions", {method:"POST", body:JSON.stringify({item_id:itemId,seller_id:user.id,price_ton:price.toFixed(9),commission_ton:AUCTION_COMMISSION_TON,status:"active"})});
      return res.status(200).json({ok:true,auction:rows?.[0]||null,commission_ton:AUCTION_COMMISSION_TON,min_price_ton:MIN_AUCTION_PRICE_TON});
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

      const auctions = await sb(`auctions?id=eq.${encodeURIComponent(auction_id)}&select=*`);
      const auction = auctions?.[0];
      if (!auction || auction.status !== "active") {
        return res.status(404).json({ ok: false, error: "auction not active" });
      }

      const itemCheck = await sb(`collectibles?id=eq.${auction.item_id}&select=is_locked,wallet_address`);
      if (itemCheck?.[0]?.is_locked) {
        return res.status(409).json({ ok: false, error: "item already locked in another pending order" });
      }

      const buyers = await sb(`users?telegram_id=eq.${verifiedUser.id}&select=*`);
      const buyer = buyers?.[0];
      if (!buyer) return res.status(404).json({ ok: false, error: "buyer not found" });

      if (buyer.id === auction.seller_id) {
        return res.status(400).json({ ok: false, error: "cannot buy your own listing" });
      }

      if (!itemCheck?.[0]?.wallet_address) return res.status(400).json({ok:false,error:"seller wallet is not connected"});
      const listingPrice = Number(auction.price_ton);
      const commission = Number(auction.commission_ton ?? AUCTION_COMMISSION_TON);
      const totalAmount = listingPrice + commission;
      // Atomically claim the card: only an unlocked card can be changed.
      // This prevents two buyers from both creating pending orders for the same item.
      const locked = await sb(`collectibles?id=eq.${auction.item_id}&is_locked=eq.false`, { method:"PATCH", body:JSON.stringify({is_locked:true}) });
      if (!locked?.length) {
        return res.status(409).json({ ok:false, error:"item already locked in another pending order" });
      }
      const memo = `deal_${auction.id.slice(0, 8)}_${Math.random().toString(36).slice(2, 9)}`;

      let orderRows;
      try {
        orderRows = await sb("orders", {
          method: "POST",
          body: JSON.stringify({
            deal_memo: memo,
            auction_id: auction.id,
            item_id: auction.item_id,
            buyer_id: buyer.id,
            seller_id: auction.seller_id,
            amount_ton: totalAmount,
            commission_ton: commission,
            service_wallet: SERVICE_WALLET,
            status: "pending",
          }),
        });
      } catch (e) {
        // Never leave a card locked if order creation itself failed.
        await sb(`collectibles?id=eq.${auction.item_id}&owner_id=eq.${auction.seller_id}`, {
          method:"PATCH", prefer:"return=minimal", body:JSON.stringify({is_locked:false})
        }).catch(()=>{});
        throw e;
      }

      return res.status(200).json({
        ok: true,
        order: orderRows[0],
        pay_to: SERVICE_WALLET,
        seller_wallet: itemCheck[0].wallet_address,
        memo,
        amount_ton: totalAmount,
        listing_price_ton: listingPrice,
        commission_ton: commission,
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

    // ---- HISTORY ---------------------------------------------------
    if (action === "my_history" && req.method === "POST") {
      const verifiedUser = getVerifiedUser(req);
      if (!verifiedUser) return res.status(401).json({ ok:false, error:"invalid or missing initData" });
      const users = await sb(`users?telegram_id=eq.${verifiedUser.id}&select=id`);
      const user = users?.[0];
      if (!user) return res.status(404).json({ ok:false, error:"user not found" });
      const [buyerOrders, sellerOrders] = await Promise.all([
        sb(`orders?buyer_id=eq.${user.id}&select=id,deal_memo,auction_id,item_id,buyer_id,seller_id,amount_ton,commission_ton,status,tx_hash,created_at,confirmed_at&order=created_at.desc&limit=50`),
        sb(`orders?seller_id=eq.${user.id}&select=id,deal_memo,auction_id,item_id,buyer_id,seller_id,amount_ton,commission_ton,status,tx_hash,created_at,confirmed_at&order=created_at.desc&limit=50`)
      ]);
      const seen = new Set();
      const orders = [...(buyerOrders||[]).map(o=>({...o,role:"buyer"})), ...(sellerOrders||[]).map(o=>({...o,role:"seller"}))].filter(o => !seen.has(o.id) && seen.add(o.id)).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)).slice(0,50);
      return res.status(200).json({ok:true,orders});
    }

    // ---- 3b) LOAD CURRENT CARD -------------------------------------
    if ((action === "get_my_cards" || action === "get_my_card") && req.method === "POST") {
      const verifiedUser = getVerifiedUser(req);
      if (!verifiedUser) return res.status(401).json({ ok: false, error: "invalid or missing initData" });
      const users = await sb(`users?telegram_id=eq.${verifiedUser.id}&select=id`);
      const user = users?.[0];
      if (!user) return res.status(404).json({ ok: false, error: "user not found" });
      const cards = await sb(`collectibles?owner_id=eq.${user.id}&select=id,serial_code,skin_id,card_password,wallet_address,title,description,visibility,transfer_count,created_at&order=created_at.asc`);
      return res.status(200).json({ ok: true, cards: cards || [], card: cards?.[0] || null });
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

    function isAdminTelegramId(id){ return String(id) === String(ADMIN_TELEGRAM_ID); }
function adminKeyboard(){
  return {inline_keyboard:[
    [{text:"📊 Статистика",callback_data:"adm:stats"},{text:"👥 Игроки",callback_data:"adm:users"}],
    [{text:"🔎 Игрок по ID",callback_data:"adm:player"},{text:"🎴 Карточки",callback_data:"adm:cards"}],
    [{text:"⚡ Зарядить всем",callback_data:"adm:charge_all"},{text:"🔓 Разблокировать всё",callback_data:"adm:unlock_all"}],
    [{text:"♻️ Сбросить streak всем",callback_data:"adm:reset_all"},{text:"➕ Выдать карточку",callback_data:"adm:grant"}],
    [{text:"🧹 Очистить просроченные сделки",callback_data:"adm:cleanup"}]
  ]};
}
function adminText(){ return "🛠 <b>Card Auction Admin</b>\n\nВыбери действие. Массовые операции требуют подтверждения."; }
async function adminEdit(chatId,messageId,text,reply_markup){ return tg("editMessageText",{chat_id:chatId,message_id:messageId,text,parse_mode:"HTML",reply_markup}); }
async function adminStats(){
  const [u,c,a,o]=await Promise.all([
    sb("users?select=id&limit=1"), sb("collectibles?select=id&limit=1"),
    sb("auctions?status=eq.active&select=id&limit=1"), sb("orders?status=eq.pending&select=id&limit=1")
  ]);
  return {users:u?.length||0,cards:c?.length||0,activeAuctions:a?.length||0,pendingOrders:o?.length||0};
}

    // ---- 4) TELEGRAM WEBHOOK ---------------------------------------
    if (req.method === "POST") {
      const update = req.body;
      const msg = update.message;
      const cb = update.callback_query;
      const webhookSecret = process.env.TELEGRAM_WEBHOOK_SECRET;
      if (webhookSecret && req.headers?.["x-telegram-bot-api-secret-token"] !== webhookSecret) return res.status(401).json({ok:false});

      if (cb) {
        if (!isAdminTelegramId(cb.from?.id)) { await tg("answerCallbackQuery",{callback_query_id:cb.id,text:"Нет доступа",show_alert:true}); return res.status(200).json({ok:true}); }
        const d=String(cb.data||""), chatId=cb.message?.chat?.id, messageId=cb.message?.message_id;
        await tg("answerCallbackQuery",{callback_query_id:cb.id});
        if(d==="adm:menu") await adminEdit(chatId,messageId,adminText(),adminKeyboard());
        else if(d==="adm:stats"){ const s=await adminStats(); await adminEdit(chatId,messageId,"📊 <b>Статистика</b>\n\n👥 Пользователи: <b>"+s.users+"</b>\n🎴 Карточки: <b>"+s.cards+"</b>\n🔨 Активные аукционы: <b>"+s.activeAuctions+"</b>\n⏳ Pending сделки: <b>"+s.pendingOrders+"</b>",{inline_keyboard:[[{text:"← Назад",callback_data:"adm:menu"}]]}); }
        else if(d==="adm:users"){ const us=await sb("users?select=telegram_id,username,first_name,daily_streak,created_at&order=created_at.desc&limit=12"); const lines=(us||[]).map((u,n)=>(n+1)+". <code>"+u.telegram_id+"</code> "+(u.username?"@"+u.username:(u.first_name||"—"))+" · streak "+(u.daily_streak||0)); await adminEdit(chatId,messageId,"👥 <b>Последние игроки</b>\n\n"+(lines.join("\n")||"Нет игроков"),{inline_keyboard:[[{text:"← Назад",callback_data:"adm:menu"}]]}); }
        else if(d==="adm:cards"){ const cs=await sb("collectibles?select=id,owner_id,serial_code,is_charged,is_locked,created_at&order=created_at.desc&limit=12"); const lines=(cs||[]).map((x,n)=>(n+1)+". #"+x.id+" · <code>"+x.serial_code+"</code> · owner "+x.owner_id+" · "+(x.is_charged?"⚡":"○")+" "+(x.is_locked?"🔒":"🔓")); await adminEdit(chatId,messageId,"🎴 <b>Последние карточки</b>\n\n"+(lines.join("\n")||"Нет карточек"),{inline_keyboard:[[{text:"← Назад",callback_data:"adm:menu"}]]}); }
        else if(d==="adm:charge_all") await adminEdit(chatId,messageId,"⚡ <b>Зарядить ВСЕ карточки?</b>",{inline_keyboard:[[{text:"Да, зарядить",callback_data:"adm:confirm_charge_all"}],[{text:"Отмена",callback_data:"adm:menu"}]]});
        else if(d==="adm:confirm_charge_all"){ await sb("collectibles",{method:"PATCH",prefer:"return=minimal",body:JSON.stringify({is_charged:true,charge_progress:100})}); await adminEdit(chatId,messageId,"✅ Все карточки заряжены.",{inline_keyboard:[[{text:"← Админ-панель",callback_data:"adm:menu"}]]}); }
        else if(d==="adm:unlock_all") await adminEdit(chatId,messageId,"🔓 <b>Разблокировать ВСЕ карточки?</b>",{inline_keyboard:[[{text:"Да, разблокировать",callback_data:"adm:confirm_unlock_all"}],[{text:"Отмена",callback_data:"adm:menu"}]]});
        else if(d==="adm:confirm_unlock_all"){ await sb("collectibles",{method:"PATCH",prefer:"return=minimal",body:JSON.stringify({is_locked:false})}); await adminEdit(chatId,messageId,"✅ Все карточки разблокированы.",{inline_keyboard:[[{text:"← Админ-панель",callback_data:"adm:menu"}]]}); }
        else if(d==="adm:reset_all") await adminEdit(chatId,messageId,"♻️ <b>Сбросить streak ВСЕМ пользователям?</b>",{inline_keyboard:[[{text:"Да, сбросить",callback_data:"adm:confirm_reset_all"}],[{text:"Отмена",callback_data:"adm:menu"}]]});
        else if(d==="adm:confirm_reset_all"){ await sb("users",{method:"PATCH",prefer:"return=minimal",body:JSON.stringify({daily_streak:0,last_shake_at:null})}); await adminEdit(chatId,messageId,"✅ Streak сброшен у всех.",{inline_keyboard:[[{text:"← Админ-панель",callback_data:"adm:menu"}]]}); }
        else if(d==="adm:cleanup"){ const n=await sb("rpc/cleanup_expired_orders",{method:"POST",body:"{}"}); await adminEdit(chatId,messageId,"🧹 Очистка завершена: <b>"+n+"</b>",{inline_keyboard:[[{text:"← Админ-панель",callback_data:"adm:menu"}]]}); }
        else if(d==="adm:player") await tg("sendMessage",{chat_id:chatId,text:"🔎 Отправь: <code>игрок 123456789</code>",parse_mode:"HTML"});
        else if(d==="adm:grant") await tg("sendMessage",{chat_id:chatId,text:"➕ Отправь: <code>выдать 123456789 1234 111111 photo_1</code>",parse_mode:"HTML"});
        return res.status(200).json({ok:true});
      }

      if(msg?.from && isAdminTelegramId(msg.from.id) && msg.text){
        const t=msg.text.trim();
        if(t==="админ" || t==="/admin"){ await tg("sendMessage",{chat_id:msg.chat.id,text:adminText(),parse_mode:"HTML",reply_markup:adminKeyboard()}); return res.status(200).json({ok:true}); }
        let m=t.match(/^игрок\s+(\d+)$/i);
        if(m){ const tid=m[1], us=await sb("users?telegram_id=eq."+tid+"&select=id,telegram_id,username,first_name,daily_streak,last_shake_at,created_at"); if(!us?.[0]){await tg("sendMessage",{chat_id:msg.chat.id,text:"Игрок не найден."});return res.status(200).json({ok:true});} const u=us[0], cs=await sb("collectibles?owner_id=eq."+u.id+"&select=id,serial_code,skin_id,is_charged,is_locked,wallet_address,title&order=created_at.desc"); await tg("sendMessage",{chat_id:msg.chat.id,text:"👤 <b>Игрок</b>\nID: <code>"+u.telegram_id+"</code>\nUsername: @"+(u.username||"нет")+"\nStreak: "+(u.daily_streak||0)+"\nКарточек: "+(cs||[]).length+"\n\n"+(cs||[]).slice(0,20).map(x=>"#"+x.id+" · <code>"+x.serial_code+"</code> · "+(x.is_charged?"⚡":"○")+" "+(x.is_locked?"🔒":"🔓")).join("\n"),parse_mode:"HTML"}); return res.status(200).json({ok:true}); }
        m=t.match(/^сброс\s+(\d+)$/i);
        if(m){ const us=await sb("users?telegram_id=eq."+m[1]+"&select=id"); if(us?.[0]){await sb("users?id=eq."+us[0].id,{method:"PATCH",body:JSON.stringify({daily_streak:0,last_shake_at:null})});await sb("collectibles?owner_id=eq."+us[0].id,{method:"PATCH",body:JSON.stringify({is_charged:false,charge_progress:0,is_locked:false})});} await tg("sendMessage",{chat_id:msg.chat.id,text:us?.[0]?"✅ Игрок сброшен.":"Игрок не найден."}); return res.status(200).json({ok:true}); }
        m=t.match(/^выдать\s+(\d+)\s+(\d{4})\s+(\d{6})\s+([A-Za-z0-9_-]+)$/i);
        if(m){ const us=await sb("users?telegram_id=eq."+m[1]+"&select=id"), dup=await sb("collectibles?serial_code=eq."+m[2]+"&select=id&limit=1"); if(!us?.[0]) await tg("sendMessage",{chat_id:msg.chat.id,text:"Игрок не найден."}); else if(dup?.[0]) await tg("sendMessage",{chat_id:msg.chat.id,text:"❌ Этот номер уже занят."}); else {const rows=await sb("collectibles",{method:"POST",body:JSON.stringify({owner_id:us[0].id,serial_code:m[2],access_key:crypto.randomUUID(),card_password:m[3],skin_id:m[4],wallet_address:null,title:"Без названия",visibility:"public"})});await tg("sendMessage",{chat_id:msg.chat.id,text:"✅ Карточка выдана. ID: "+(rows?.[0]?.id||"—")});} return res.status(200).json({ok:true}); }
      }

      if(msg && msg.text && msg.text.startsWith("/start")){
        await sb("users",{method:"POST",prefer:"resolution=merge-duplicates,return=representation",headers:{"Content-Type":"application/json"},body:JSON.stringify({telegram_id:msg.from.id,username:msg.from.username||null,first_name:msg.from.first_name||null})}).catch(()=>{});
        await tg("sendMessage",{chat_id:msg.chat.id,text:"💳 *Card Auction* — collect, charge & trade rare cards on TON.\n\nTap below to open the vault.",parse_mode:"Markdown",reply_markup:{inline_keyboard:[[{text:"🚀 Open Card Auction",web_app:{url:APP_URL}}]]}});
      }
      return res.status(200).json({ok:true});
    }
    // ---- default ----------------------------------------------------
    return res.status(200).json({ ok: true, service: "card-vault-bot", status: "alive" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: err.message });
  }
}
