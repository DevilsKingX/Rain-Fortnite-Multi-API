import 'dotenv/config';
import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.DATABASE_URL, process.env.DATABASE_KEY);


const app = express();
app.use(cors());
app.use(express.json());

const PORT = 4000;

// Load access codes
const codesPath = path.resolve("data/accessCodes.json");
let accessCodes = JSON.parse(fs.readFileSync(codesPath, "utf8"));

// Load private key for signing
const privateKey = fs.readFileSync(path.resolve("private.pem"), "utf8");

// Helper: sign any object
function signResponse(data) {
  const jsonString = JSON.stringify(data);
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(jsonString);
  signer.end();

  const signature = signer.sign(privateKey, "base64");

  return { ...data, signature };
}

app.post("/api/verifyAccessCode", async (req, res) => {
  const { accessCode, xCode } = req.body;

  if (!accessCode || !xCode) {
    return res.status(400).json(
      signResponse({
        valid: false,
        message: "Missing accessCode or xCode"
      })
    );
  }

  const { data: codeEntry } = await supabase
    .from("access_codes")
    .select("*")
    .eq("code", accessCode)
    .single();


  if (!codeEntry) {
    return res.json(
      signResponse({
        valid: false,
        message: "Invalid or expired access code"
      })
    );
  }

  const now = new Date();
const expirationRaw = codeEntry.expirationDate || codeEntry.expiration_date;

const expirationDate = new Date(String(expirationRaw).trim());

  if (expirationDate < now) {
    return res.json(
      signResponse({
        valid: false,
        message: "Invalid or expired access code"
      })
    );
  }

  // Handle machine binding
  if (!codeEntry.xCode) {
    // First activation: store machine ID
    codeEntry.xCode = xCode;

    // Save updated file
    fs.writeFileSync(codesPath, JSON.stringify(accessCodes, null, 2));
  } else if (codeEntry.xCode !== xCode) {
    return res.json(
      signResponse({
        valid: false,
        message: "Access key already used on another machine"
      })
    );
  }
  
console.log("expirationDate from db:", codeEntry.expiration_date);
  // Success response
  const responseData = {
    valid: true,
    expirationDate: expirationDate.toISOString(),
    message: `Access granted until ${expirationDate.toDateString()}`,
    machineLock: true
  };

  return res.json(signResponse(responseData));
});

app.listen(PORT, () => {
  console.log(`Access server running on http://localhost:${PORT}`);
});
