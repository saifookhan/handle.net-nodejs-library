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

// app.get("/update-handle/:handle", async (req, res) => {
//   const handle = req.params.handle;
//   const result = await updateHandleRecord(
//     `${prefix}/${handle}`,
//     pathToPrivateKeyPemFile,
//     adminId,
//     ip,
//     serverPort
//   );
//   res.json(result);
// });

// app.delete("/delete-handle/:handle", async (req, res) => {
//   const handle = req.params.handle;
//   const result = await deleteHandleRecord(
//     `${prefix}/${handle}`,
//     pathToPrivateKeyPemFile,
//     adminId,
//     ip,
//     serverPort
//   );
//   res.json(result);
// });

// const getEmailValue = (handle) => {
//   return handle.find((item) => item.index === 2) || null;
// };

// const getHandleRecord = async (handle, ip, port) => {
//   const url = `https://${ip}:${port}/api/handles/${handle}`;
//   const response = await fetch(url, {
//     agent: new https.Agent({ rejectUnauthorized: false }),
//   });
//   return response.json();
// };

// const updateHandleRecord = async (handle, keyFile, authId, ip, port) => {
//   const handleRecord = await getHandleRecord(handle, ip, port);
//   console.log(handleRecord);

//   let emailValue = getEmailValue(handleRecord.values);
//   if (!emailValue) {
//     const currentDate = DateTime.now().toISO();
//     handleRecord.values.push({
//       index: 2,
//       ttl: 86400,
//       type: "EMAIL",
//       timestamp: currentDate,
//       data: { value: "info@thenbs.com", format: "string" },
//     });
//   } else {
//     emailValue.data.value = "info@theNBS.com";
//   }
//   console.log(handleRecord);

//   const headers = { "Content-Type": "application/json;charset=UTF-8" };
//   const url = `https://${ip}:${port}/api/handles/${handle}`;
//   const body = JSON.stringify(handleRecord);

//   let response = await fetch(url, {
//     method: "PUT",
//     headers,
//     body,
//     agent: new https.Agent({ rejectUnauthorized: false }),
//   });
//   console.log('headers[["Authorization"]]');

//   headers["Authorization"] = await createAuthorisationHeader(
//     response,
//     keyFile,
//     authId
//   );
//   console.log(headers[["Authorization"]]);

//   response = await fetch(url, {
//     method: "PUT",
//     headers,
//     body,
//     agent: new https.Agent({ rejectUnauthorized: false }),
//   });
//   console.log(response.status, response.statusText);

//   return response.json();
// };

// const createHandleRecord = async (handle, keyFile, authId, ip, port) => {
//   const currentDate = DateTime.now().toISO();
//   const handleRecord = {
//     values: [
//       {
//         index: 1,
//         ttl: 86400,
//         type: "URL",
//         timestamp: currentDate,
//         data: { value: "http://www.ribaenterprises.com", format: "string" },
//       },
//       {
//         index: 2,
//         ttl: 86400,
//         type: "EMAIL",
//         timestamp: currentDate,
//         data: { value: "info@ribaenterprises.com", format: "string" },
//       },
//       {
//         index: 100,
//         ttl: 86400,
//         type: "HS_ADMIN",
//         timestamp: currentDate,
//         data: {
//           value: { index: 200, handle: authId, permissions: "011111110011" },
//           format: "admin",
//         },
//       },
//     ],
//     handle,
//     responseCode: 1,
//   };

//   const headers = { "Content-Type": "application/json;charset=UTF-8" };
//   const url = `https://${ip}:${port}/api/handles/${handle}`;
//   const body = JSON.stringify(handleRecord);

//   let response = await fetch(url, {
//     method: "PUT",
//     headers,
//     body,
//     agent: new https.Agent({ rejectUnauthorized: false }),
//   });

//   console.log('headers[["Authorization"]]');

//   headers["Authorization"] = await createAuthorisationHeader(
//     response,
//     keyFile,
//     authId
//   );

//   console.log(headers[["Authorization"]]);

//   response = await fetch(url, {
//     method: "PUT",
//     headers,
//     body,
//     agent: new https.Agent({ rejectUnauthorized: false }),
//   });

//   console.log(response.status, response.statusText);

//   return response.json();
// };

// const deleteHandleRecord = async (handle, keyFile, authId, ip, port) => {
//   const headers = { "Content-Type": "application/json;charset=UTF-8" };
//   const url = `https://${ip}:${port}/api/handles/${handle}`;

//   let response = await fetch(url, {
//     method: "DELETE",
//     headers,
//     agent: new https.Agent({ rejectUnauthorized: false }),
//   });

//   headers["Authorization"] = await createAuthorisationHeader(
//     response,
//     keyFile,
//     authId
//   );

//   response = await fetch(url, {
//     method: "DELETE",
//     headers,
//     agent: new https.Agent({ rejectUnauthorized: false }),
//   });
//   console.log(response.status, response.statusText);

//   return response.json();
// };

// const createAuthorisationHeader = async (response, keyFile, authId) => {
//   const authenticateHeader = response.headers.get("www-authenticate");
//   const authenticateHeaderDict = parseAuthenticateHeader(authenticateHeader);
//   const serverNonceBytes = Buffer.from(authenticateHeaderDict.nonce, "base64");
//   const sessionId = authenticateHeaderDict.sessionId;

//   const clientNonceBytes = await generateClientNonceBytes();
//   const clientNonceString = clientNonceBytes.toString("base64");

//   const combinedNonceBytes = Buffer.concat([
//     serverNonceBytes,
//     clientNonceBytes,
//   ]);
//   console.log("testtttttt");

//   const signatureBytes = signBytesDSA(combinedNonceBytes, keyFile);
//   const signatureString = signatureBytes.toString("base64");

//   const authorizationHeaderString = buildComplexAuthorizationString(
//     signatureString,
//     "HS_PUBKEY",
//     "SHA1",
//     sessionId,
//     clientNonceString,
//     authId
//   );

//   return authorizationHeaderString;
// };

// const signBytesRSA = (byteArray, pathToPrivateKeyPemFile) => {
//   const key = fs.readFileSync(pathToPrivateKeyPemFile, "utf8");
//   const rsaKey = crypto.createPrivateKey(key);
//   const sign = crypto.createSign("SHA256");
//   sign.update(byteArray);
//   sign.end();
//   return sign.sign(rsaKey);
// };

// const signBytesDSA = (byteArray, pathToPrivateKeyPemFile) => {
//   const key = fs.readFileSync(pathToPrivateKeyPemFile, "utf8");
//   console.log("KEY", key);
//   const dsaKey = crypto.createPrivateKey({
//     format: "pem",
//     key: key,
//     passphrase: "temppass@1981",
//   });
//   console.log("pathToPrivateKeyPemFile", pathToPrivateKeyPemFile);
//   const sign = crypto.createSign("SHA1");
//   sign.update(byteArray);
//   sign.end();
//   const signature = sign.sign(dsaKey);

//   // Use asn1.js to encode the signature as a DER sequence
//   const DerSequence = asn1.define("DerSequence", function () {
//     this.seq().obj(this.key("r").int(), this.key("s").int());
//   });

//   // Extract r and s from the signature buffer
//   const half = Math.ceil(signature.length / 2);
//   const r = signature.slice(0, half);
//   const s = signature.slice(half);

//   const signatureDer = DerSequence.encode({ r: r, s: s }, "der");

//   return signatureDer;

//   const seq = new crypto.DerSequence();
//   seq.append(signature);
//   return seq.encode();
// };

// const buildComplexAuthorizationString = (
//   signatureString,
//   typeString,
//   alg,
//   sessionId,
//   clientNonceString,
//   authId
// ) => {
//   console.log("test");

//   return `Handle version="0", sessionId="${sessionId}", cnonce="${clientNonceString}", id="${authId}", type="${typeString}", alg="${alg}", signature="${signatureString}"`;
// };

// const parseAuthenticateHeader = (authenticateHeader) => {
//   const result = {};
//   const tokens = authenticateHeader.split(", ");

//   tokens.forEach((token) => {
//     const [key, value] = token.split("=");
//     if (key === "Basic realm") return;
//     if (key === "Handle sessionId") result.sessionId = value.slice(1, -1);
//     else result[key] = value.slice(1, -1);
//   });

//   return result;
// };

// const generateClientNonceBytes = async () => {
//   return crypto.randomBytes(16);
// };
