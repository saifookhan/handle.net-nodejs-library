import express from "express";
import fs from "fs";
import https from "https";
import { DateTime } from "luxon";
import crypto from "node:crypto";
import dotenv from "dotenv";
import asn1 from "asn1.js";
import { HandleRestApi, loadPrivateKey } from "./handle.js";
dotenv.config();

const app = express();
const port = 8001;
const myServerIp = process.env.HANDLE_SERVER_IP_ADDRESS;

app.use(express.json());
app.use((req, res, next) => {
  // res.setHeader('Access-Control-Allow-Origin', 'https://repod-test.zbw.eu');
  res.setHeader('Access-Control-Allow-Origin', '*');
  // Add other CORS headers as needed
  next();
});
const pathToPrivateKeyPemFile = process.env.PRIVATE_PEM_KEY_PATH;
const pathToPrivateKeyJwkFile = process.env.PRIVATE_JWK_KEY_PATH;
const adminId = process.env.ADMIN_ID;
const prePrefix = process.env.PREPREFIX;
const prefix = process.env.PREFIX;
const ip = process.env.HANDLE_SERVER_IP_ADDRESS;
const handleServerPort = process.env.HANDLE_SERVER_PORT;
let serverUrl = `https://${ip}:${handleServerPort}`;
const pathToHttpsKeyFile = process.env.HTTPS_KEY_FILE_PATH;
const pathToHttpsPemFile = process.env.HTTPS_PEM_FILE_PATH;
let privateJwkKey = await loadPrivateKey(pathToPrivateKeyJwkFile);

const auth = {
  adminIndex: 300,
  adminHandle: prePrefix + "/" + prefix,
  privateKey: privateJwkKey,
  mode: "HS_PUBKEY",
};

app.post("/create-handle/:handle", async (req, res) => {
  const handle = req.params.handle;

  let handleRestApi = new HandleRestApi(auth, serverUrl);

  let completeHandle = `${prefix}/${handle}`;
  let handleValues = [
    {
      index: 1,
      type: "URL",
      data: {
        format: "string",
        value: "https://example.com",
      },
    },
    {
      index: 100,
      type: "HS_ADMIN",
      data: {
        format: "admin",
        value: {
          handle: auth.adminHandle,
          index: auth.adminIndex,
          permissions: "011111110011",
        },
      },
    },
  ];

  let createResult = await handleRestApi.createHandle(
    completeHandle,
    handleValues
  );
  console.log(createResult);
  res.json(createResult);
});

// GET /get-handle-info?handleId=123456handleUrl=https://example.com
app.get("/get-handle-info", async (req, res) => {
  const handle = req.query.handleId;
  const value = req.query.handleUrl; // Retrieve the value from the query parameters

  let handleRestApi = new HandleRestApi(auth, serverUrl);

  let completeHandle = `${prefix}/${handle}`;
  let handleValues = [
    {
      index: 1,
      type: "URL",
      data: {
        format: "string",
        value: value, // Use the value from the query parameters
      },
    },
    {
      index: 100,
      type: "HS_ADMIN",
      data: {
        format: "admin",
        value: {
          handle: auth.adminHandle,
          index: auth.adminIndex,
          permissions: "011111110011",
        },
      },
    },
  ];

  let createResult = await handleRestApi.createHandle(
    completeHandle,
    handleValues
  );
  console.log(createResult);
  res.json(createResult);
});

app.use((err, req, res, next) => {
  if (err) {
    return res.status(err.statusCode || 500).json(err.message);
  }
  next();
});

const privateKey = fs.readFileSync(pathToHttpsKeyFile, "utf8");
const certificate = fs.readFileSync(pathToHttpsPemFile, "utf8");
const credentials = { key: privateKey, cert: certificate };
const httpsServer = https.createServer(credentials, app);
const PORT = port || 443;

httpsServer.listen(PORT, myServerIp, () => {
  console.log(
    `Server running at https://localhost:${port}/ for Handle Sever: ${ip}, ${pathToPrivateKeyJwkFile}`
  );
});

const httpPort = port + 1;
app.listen(httpPort, myServerIp, () => {
  console.log(
    `Server running at http://localhost:${httpPort}/ for Handle Sever: ${ip}, ${pathToPrivateKeyJwkFile}`
  );
});
