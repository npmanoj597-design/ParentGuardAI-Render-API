
const express = require("express");
const crypto = require("crypto");
const {
  initializeApp,
  cert,
} = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getDatabase } = require("firebase-admin/database");

const app = express();
app.use(express.json({ limit: "10kb" }));

const PORT = process.env.PORT || 10000;
const CODE_LIFETIME_MS = 10 * 60 * 1000;
const STALE_RESERVATION_MS = 2 * 60 * 1000;

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

    // Verify the Firebase ID token and its custom role claim.
    const decoded = await auth.verifyIdToken(match[1]);

    req.uid = decoded.uid;
    req.role = decoded.role;

    if (req.role !== "Parent" && req.role !== "Child") {
      throw makeError(
        403,
        "Your account does not have a valid role"
      );
    }

    next();
  } catch (error) {
    res.status(error.status || 401).json({
      error: error.status
        ? error.message
        : "Authentication failed",
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

// POST /createPairingCode
app.post("/createPairingCode", requireRole, async (req, res) => {
  try {
    if (req.role !== "Parent") {
      throw makeError(
        403,
        "Only parent accounts can create pairing codes"
      );
    }

    await checkProfile(req.uid, "Parent");

    const code = crypto.randomInt(100000, 1000000).toString();
    const now = Date.now();
    const expiresAt = now + CODE_LIFETIME_MS;

    await db.ref(`pairingCodes/${req.uid}`).set({
      parentUid: req.uid,
      codeHash: hashCode(code),
      createdAt: now,
      expiresAt,
      used: false,
    });

    console.log("Pairing code created", { parentUid: req.uid });

    res.json({ code, expiresAt });
  } catch (error) {
    console.error("Create pairing code failed:", error.message);

    res.status(error.status || 500).json({
      error: error.status
        ? error.message
        : "Could not create pairing code",
    });
  }
});

// POST /redeemPairingCode
// Request JSON: {"code":"123456"}
app.post("/redeemPairingCode", requireRole, async (req, res) => {
  const childUid = req.uid;

  let reservationId = null;
  let reservationCreated = false;
  let codeConsumed = false;
  let codePath = null;
  let parentUid = null;

  try {
    if (req.role !== "Child") {
      throw makeError(
        403,
        "Only child accounts can redeem pairing codes"
      );
    }

    const code = String(req.body?.code ?? "").trim();

    if (!/^\d{6}$/.test(code)) {
      throw makeError(
        400,
        "Enter a valid six-digit pairing code"
      );
    }

    await checkProfile(childUid, "Child");

    const submittedHash = hashCode(code);
    const codesSnapshot = await db.ref("pairingCodes").get();
    const codes = codesSnapshot.val() || {};

    // Find the parent whose stored code hash matches.
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
  console.error("Pairing lookup failed: no matching code hash", {
    childUid,
    numberOfCodeRecords: Object.keys(codes).length,
  });

  throw makeError(
    400,
    "Invalid or expired pairing code. Request a new code."
  );
}

    if (parentUid === childUid) {
      throw makeError(
        400,
        "A parent account cannot pair with itself"
      );
    }

    await checkProfile(parentUid, "Parent");

    codePath = `pairingCodes/${parentUid}`;

    // Reserve this child's parentOf record atomically.
    // Existing completed links are never overwritten.
    reservationId = crypto.randomUUID();
    const parentOfRef = db.ref(`parentOf/${childUid}`);
    const now = Date.now();

    const reservation = await parentOfRef.transaction((current) => {
      if (current === null) {
        return {
          parentUid,
          status: "pending",
          reservedAt: now,
          reservationId,
        };
      }

      // A completed relationship must not be overwritten.
      if (current.status !== "pending" || current.linkedAt) {
        return;
      }

      const pendingSince = Number(current.reservedAt || 0);
      const isStale =
        pendingSince > 0 &&
        now - pendingSince > STALE_RESERVATION_MS;

      if (!isStale) {
        return;
      }

      // Reclaim only an expired pending reservation.
      return {
        parentUid,
        status: "pending",
        reservedAt: now,
        reservationId,
      };
    }, undefined, false);

    if (!reservation.committed) {
      const current = reservation.snapshot.val();

      if (current && current.status === "pending") {
        throw makeError(
          409,
          "A pairing attempt is already in progress. If it remains stuck, wait two minutes and try again."
        );
      }

      throw makeError(
        409,
        "This child is already linked to a parent"
      );
    }

    reservationCreated = true;

    // Consume the code atomically and log the reason if rejected.
const consumed = await db.ref(codePath).transaction((current) => {
  if (!current) {
    return;
  }

  if (current.parentUid !== parentUid) {
    return;
  }

  if (current.codeHash !== submittedHash) {
    return;
  }

  if (current.used !== false) {
    return;
  }

  if (
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
  const latestSnapshot = await db.ref(codePath).get();
  const latest = latestSnapshot.val();

  console.error("Pairing code transaction rejected", {
    parentUid,
    childUid,
    codeRecordExists: Boolean(latest),
    parentUidMatches: latest?.parentUid === parentUid,
    codeHashMatches: latest?.codeHash === submittedHash,
    usedValue: latest?.used,
    expiresAt: latest?.expiresAt,
    now: Date.now(),
    isExpired:
      typeof latest?.expiresAt === "number" &&
      latest.expiresAt <= Date.now(),
  });

  throw makeError(
    400,
    "The pairing code is invalid, expired, or already used. Generate a new code."
  );
}

codeConsumed = true;

    // Verify this request still owns the reservation.
    const linkedAt = Date.now();

    const finalizeReservation = await parentOfRef.transaction(
      (current) => {
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
      },
      undefined,
      false
    );

    if (!finalizeReservation.committed) {
      throw makeError(
        409,
        "The pairing reservation changed. Please generate a new code."
      );
    }

    // Store the matching parent -> child relationship.
    await db.ref(`parentChildren/${parentUid}/${childUid}`).set({
      linkedAt,
    });

    reservationCreated = false;

    console.log("Parent-child pairing completed", {
      parentUid,
      childUid,
    });

    return res.json({
      success: true,
      message: "Parent and child linked successfully",
      parentUid,
    });
  } catch (error) {
    console.error("Pairing request failed:", error.message);

    // Roll back only a pending reservation created by this request.
    if (reservationCreated && reservationId) {
      try {
        await db.ref(`parentOf/${childUid}`).transaction((current) => {
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
        console.error("Could not release pairing reservation");
      }
    }

    if (codeConsumed) {
      console.error(
        "Pairing code was consumed. Generate a fresh code before retrying."
      );
    }

    if (!res.headersSent) {
      res.status(error.status || 500).json({
        error: error.status
          ? error.message
          : "Could not complete pairing. Please try again.",
      });
    }
  }
});

// General Express error handler.
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
