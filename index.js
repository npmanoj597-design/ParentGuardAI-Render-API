const express = require("express");
const crypto = require("crypto");
const { initializeApp, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getDatabase } = require("firebase-admin/database");

const app = express();
app.use(express.json({ limit: "10kb" }));

const PORT = process.env.PORT || 10000;
const CODE_LIFETIME_MS = 10 * 60 * 1000;
const databaseUrl = process.env.FIREBASE_DATABASE_URL;
const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!databaseUrl || !serviceAccountJson) {
  throw new Error(
    "Missing FIREBASE_DATABASE_URL or FIREBASE_SERVICE_ACCOUNT_JSON"
  );
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(serviceAccountJson);
} catch {
  throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON");
}

initializeApp({
  credential: cert(serviceAccount),
  databaseURL: databaseUrl,
});

const db = getDatabase();
const auth = getAuth();
function hashCode(code) {
  return crypto.createHash("sha256").update(code).digest("hex");
}

function makeError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

async function requireRole(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer (.+)$/i);

    if (!match) {
      throw makeError(401, "Missing Firebase ID token");
    }

    const decoded = await auth.verifyIdToken(match[1]);
    req.uid = decoded.uid;
    req.role = decoded.role;

    if (req.role !== "Parent" && req.role !== "Child") {
      throw makeError(403, "Your account does not have a valid role");
    }

    next();
  } catch (error) {
    res.status(error.status || 401).json({
      error: error.status ? error.message : "Authentication failed",
    });
  }
}

async function checkProfile(uid, expectedRole) {
  const snapshot = await db.ref(`users/${uid}`).get();
  const profile = snapshot.val();

  if (!profile || profile.role !== expectedRole) {
    throw makeError(403, `A valid ${expectedRole} profile is required`);
  }
}

app.get("/", (req, res) => {
  res.json({ service: "ParentGuard AI API", status: "running" });
});

app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

// POST /createPairingCode
app.post("/createPairingCode", requireRole, async (req, res) => {
  try {
    if (req.role !== "Parent") {
      throw makeError(403, "Only parent accounts can create pairing codes");
    }

    await checkProfile(req.uid, "Parent");

    const code = crypto.randomInt(100000, 1000000).toString();
    const now = Date.now();

    await db.ref(`pairingCodes/${req.uid}`).set({
      parentUid: req.uid,
      codeHash: hashCode(code),
      createdAt: now,
      expiresAt: now + CODE_LIFETIME_MS,
      used: false,
    });

    res.json({
      code,
      expiresAt: now + CODE_LIFETIME_MS,
    });
  } catch (error) {
    res.status(error.status || 500).json({
      error: error.status ? error.message : "Could not create pairing code",
    });
  }
});

// POST /redeemPairingCode with JSON body: {"code":"123456"}
app.post("/redeemPairingCode", requireRole, async (req, res) => {
  let reservedParentPath = null;
  let reservedParentUid = null;
  let reservedAt = null;
  let codePath = null;
  let codeConsumed = false;

  try {
    if (req.role !== "Child") {
      throw makeError(403, "Only child accounts can redeem pairing codes");
    }

    const code = String(req.body?.code ?? "").trim();

    if (!/^\d{6}$/.test(code)) {
      throw makeError(400, "Enter a valid six-digit pairing code");
    }

    await checkProfile(req.uid, "Child");

    const existingParent = await db.ref(`parentOf/${req.uid}`).get();
    if (existingParent.exists()) {
      throw makeError(409, "This child is already linked to a parent");
    }

    // Locate the code by its hash; plaintext codes are never stored.
    const codesSnapshot = await db.ref("pairingCodes").get();
    const codes = codesSnapshot.val() || {};
    const submittedHash = hashCode(code);
    let parentUid = null;

    for (const [uid, record] of Object.entries(codes)) {
      if (
        record &&
        typeof record.codeHash === "string" &&
        record.codeHash === submittedHash
      ) {
        parentUid = uid;
        break;
      }
    }

    if (!parentUid) {
      throw makeError(400, "Invalid or expired pairing code");
    }

    await checkProfile(parentUid, "Parent");

    codePath = `pairingCodes/${parentUid}`;

    // Reserve this child so concurrent attempts cannot link them
    // to different parents.
    reservedParentPath = `parentOf/${req.uid}`;
    reservedParentUid = parentUid;
    reservedAt = Date.now();

    const reservation = await db.ref(reservedParentPath).transaction(
      (current) => {
        if (current !== null) return;
        return {
          parentUid,
          status: "pending",
          reservedAt,
        };
      },
      undefined,
      false
    );

    if (!reservation.committed) {
      reservedParentPath = null;
      throw makeError(409, "This child is already linked or being linked");
    }

    // Atomically consume the code. Only one request can succeed.
    const consumed = await db.ref(codePath).transaction((current) => {
      if (
        !current ||
        current.parentUid !== parentUid ||
        current.codeHash !== submittedHash ||
        current.used === true ||
        typeof current.expiresAt !== "number" ||
        current.expiresAt <= Date.now()
      ) {
        return;
      }

      return {
        ...current,
        used: true,
        usedBy: req.uid,
        usedAt: Date.now(),
      };
    }, undefined, false);

    if (!consumed.committed) {
      throw makeError(400, "Invalid, expired, or already-used pairing code");
    }

    codeConsumed = true;

    // Complete the relationship with a single multi-location update.
    const linkedAt = Date.now();
    const updates = {};

    updates[`parentChildren/${parentUid}/${req.uid}`] = { linkedAt };
    updates[`parentOf/${req.uid}`] = { parentUid, linkedAt };

    await db.ref().update(updates);

    reservedParentPath = null;

    res.json({
      success: true,
      message: "Parent and child linked successfully",
      parentUid,
    });
  } catch (error) {
    // Release only our own pending reservation if pairing failed.
    if (reservedParentPath && reservedParentUid) {
      try {
        await db.ref(reservedParentPath).transaction((current) => {
          if (
            current &&
            current.parentUid === reservedParentUid &&
            current.status === "pending" &&
            current.reservedAt === reservedAt
          ) {
            return null;
          }
          return;
        }, undefined, false);
      } catch (rollbackError) {
        console.error("Could not release pairing reservation");
      }
    }

    if (codeConsumed) {
      console.error(
        "Pairing code was consumed but relationship completion failed"
      );
    }

    res.status(error.status || 500).json({
      error: error.status ? error.message : "Could not redeem pairing code",
    });
  }
});

app.use((err, req, res, next) => {
  console.error("Unhandled API error:", err.message);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`ParentGuard AI API listening on port ${PORT}`);
});
