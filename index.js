
const express = require("express");
const crypto = require("crypto");

const { initializeApp, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getDatabase } = require("firebase-admin/database");

const app = express();
app.use(express.json({ limit: "10kb" }));

const PORT = process.env.PORT || 10000;
const QR_LIFETIME_MS = 2 * 60 * 1000;

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

function makeError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
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
      // Fallback: If custom claim is not in the token, fetch role from Realtime Database profile
      const userSnap = await db.ref(`users/${req.uid}`).get();
      const profile = userSnap.val();
      const dbRole = profile?.role;
      if (dbRole === "Parent" || dbRole === "Child") {
        req.role = dbRole;
        // Asynchronously set custom user claim so future ID tokens include it
        auth.setCustomUserClaims(req.uid, { role: dbRole }).catch(() => {});
      }
    }

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
    throw makeError(
      403,
      `A valid ${expectedRole} profile is required`
    );
  }
}

app.get("/", (req, res) => {
  res.json({
    service: "ParentGuard AI API",
    status: "running",
  });
});

app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

// Parent creates a short-lived QR pairing token.
app.post("/createPairingQR", requireRole, async (req, res) => {
  try {
    if (req.role !== "Parent") {
      throw makeError(403, "Only parents can create pairing QR codes");
    }

    await checkProfile(req.uid, "Parent");

    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashToken(token);
    const now = Date.now();
    const expiresAt = now + QR_LIFETIME_MS;

    const tokenRef = db.ref(`pairingQrTokens/${tokenHash}`);

    await tokenRef.set({
      parentUid: req.uid,
      createdAt: now,
      expiresAt,
      used: false,
    });

    console.log("QR pairing token created", {
      parentUid: req.uid,
      expiresAt,
    });

    res.json({
      token,
      expiresAt,
      expiresInSeconds: QR_LIFETIME_MS / 1000,
    });
  } catch (error) {
    console.error("Create QR pairing token failed:", error.message);

    res.status(error.status || 500).json({
      error: error.status
        ? error.message
        : "Could not create QR pairing token",
    });
  }
});

// Child submits the token scanned from the parent's QR code.
app.post("/redeemPairingQR", requireRole, async (req, res) => {
  const childUid = req.uid;
  let tokenRef = null;
  let reservationRef = null;
  let reservationId = null;
  let reservationCreated = false;
  let tokenConsumed = false;

  try {
    if (req.role !== "Child") {
      throw makeError(403, "Only child accounts can scan parent QR codes");
    }

    await checkProfile(childUid, "Child");

    const token = String(req.body?.token ?? "").trim();

    if (!/^[a-f0-9]{64}$/i.test(token)) {
      throw makeError(400, "Invalid QR pairing token");
    }

    const tokenHash = hashToken(token);
    tokenRef = db.ref(`pairingQrTokens/${tokenHash}`);

    const tokenSnapshot = await tokenRef.get();
    const tokenRecord = tokenSnapshot.val();

    if (
      !tokenRecord ||
      typeof tokenRecord.parentUid !== "string" ||
      tokenRecord.used !== false ||
      typeof tokenRecord.expiresAt !== "number" ||
      tokenRecord.expiresAt <= Date.now()
    ) {
      throw makeError(400, "QR code is invalid or expired. Ask the parent to generate a new one.");
    }

    const parentUid = tokenRecord.parentUid;

    if (parentUid === childUid) {
      throw makeError(400, "A parent account cannot pair with itself");
    }

    await checkProfile(parentUid, "Parent");

    reservationRef = db.ref(`parentOf/${childUid}`);
    reservationId = crypto.randomUUID();

    const reservationTime = Date.now();

    const reservation = await reservationRef.transaction((current) => {
      if (current === null) {
        return {
          parentUid,
          status: "pending",
          reservedAt: reservationTime,
          reservationId,
        };
      }

      // Never overwrite an existing completed relationship.
      return;
    }, undefined, false);

    if (!reservation.committed) {
      const existing = reservation.snapshot.val();

      if (existing && existing.status === "pending") {
        throw makeError(409, "A pairing attempt is already in progress");
      }

      throw makeError(409, "This child is already linked to a parent");
    }

    reservationCreated = true;

    // Atomically consume the QR token so it cannot be reused.
    const consumed = await tokenRef.transaction((current) => {
      if (
        !current ||
        current.parentUid !== parentUid ||
        current.used !== false ||
        typeof current.expiresAt !== "number" ||
        current.expiresAt <= Date.now()
      ) {
        return;
      }

      return {
        ...current,
        used: true,
        usedBy: childUid,
        usedAt: Date.now(),
      };
    }, undefined, false);

    if (!consumed.committed) {
      throw makeError(400, "QR code is invalid, expired, or already used. Ask the parent for a new QR code.");
    }

    tokenConsumed = true;

    const linkedAt = Date.now();

    // Finalize only the reservation created by this request.
    const finalized = await reservationRef.transaction((current) => {
      if (
        !current ||
        current.status !== "pending" ||
        current.reservationId !== reservationId
      ) {
        return;
      }

      return {
        parentUid,
        linkedAt,
      };
    }, undefined, false);

    if (!finalized.committed) {
      throw makeError(409, "Pairing could not be finalized. Generate a new QR code.");
    }

    await db.ref(`parentChildren/${parentUid}/${childUid}`).set({
      linkedAt,
    });

    // Also sync the relationship under /users for direct mobile UI updates
    await db.ref(`users/${childUid}/parentId`).set(parentUid);
    await db.ref(`users/${childUid}/parentLinked`).set(true);
    await db.ref(`users/${parentUid}/children/${childUid}`).set({
      linkedAt,
    });

    reservationCreated = false;

    console.log("QR parent-child pairing completed", {
      parentUid,
      childUid,
    });

    res.json({
      success: true,
      message: "Parent and child linked successfully",
      parentUid,
    });
  } catch (error) {
    console.error("QR pairing failed:", error.message);

    // Release only the pending reservation created by this request.
    if (reservationCreated && reservationRef && reservationId) {
      try {
        await reservationRef.transaction((current) => {
          if (
            current &&
            current.status === "pending" &&
            current.reservationId === reservationId
          ) {
            return null;
          }

          return;
        }, undefined, false);
      } catch (rollbackError) {
        console.error("Could not release QR pairing reservation");
      }
    }

    if (tokenConsumed) {
      console.error(
        "QR token was consumed. Generate a fresh QR code before retrying."
      );
    }

    if (!res.headersSent) {
      res.status(error.status || 500).json({
        error: error.status
          ? error.message
          : "Could not complete QR pairing. Please try again.",
      });
    }
  }
});

app.use((err, req, res, next) => {
  console.error("Unhandled API error:", err.message);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: "Internal server error",
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`ParentGuard AI API listening on port ${PORT}`);
});
