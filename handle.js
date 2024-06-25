import { inspect } from "util";
inspect.defaultOptions.depth = null;
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;
import fs from "fs/promises";
import crypto from "crypto";
const { webcrypto } = crypto;
import https from "https";

export class HandleRestApi {
  constructor(authInfo, serverUrl) {
    this.authInfo = authInfo;
    this.serverUrl = serverUrl;
    this.clientNonceString = null;
    this.clientNonceBytes = null;
    this.sessionId = null;
  }

  async authenticate() {
    this.clientNonceBytes = this.generateClientNonceBytes();
    this.clientNonceString = this.clientNonceBytes.toString("base64");
    let authResult = await this.startSession();
    if (!authResult.authenticated) {
      this.sessionId = null;
      console.log(authResult);
      throw new Error(authResult.error);
    }
    console.log("Authenticated, sessionId: " + authResult.sessionId);
    this.sessionId = authResult.sessionId;
    return authResult;
  }

  async startSession() {
    let url = this.serverUrl + "/api/sessions";
    const response = await this.sendPostRequest(url, null, null);
    console.log(response);
    let serverNonceString = response.nonce;
    this.sessionId = response.sessionId;
    let serverNonceBytes = Buffer.from(serverNonceString, "base64");
    if (this.authInfo.mode === "HS_PUBKEY") {
      let combinedNonceBytes = this.concatBytes(
        serverNonceBytes,
        this.clientNonceBytes
      );
      let signatureString = null;
      if (this.authInfo.privateKey.kty === "DSA") {
        signatureString = await this.signDsaSha1(
          this.authInfo.privateKey,
          combinedNonceBytes
        );
      } else {
        signatureString = await this.signRsaSha1(
          this.authInfo.privateKey,
          combinedNonceBytes
        );
      }
      let authResult = await this.sendAuthentication(
        signatureString,
        "HS_PUBKEY"
      );
      console.log(authResult);
      return authResult;
    } else if (this.authInfo.mode === "HS_SECKEY") {
      //TODO
    }
  }

  async sendPostRequest(url, data, authorizationHeaderString) {
    console.log("Sending POST " + url);
    return await this.sendHttpRequest(
      "post",
      url,
      data,
      authorizationHeaderString
    );
  }

  async sendPutRequest(url, data, authorizationHeaderString) {
    console.log("Sending PUT " + url);
    return await this.sendHttpRequest(
      "put",
      url,
      data,
      authorizationHeaderString
    );
  }

  async sendGetRequest(url, authorizationHeaderString) {
    console.log("Sending GET " + url);
    return await this.sendHttpRequest(
      "get",
      url,
      null,
      authorizationHeaderString
    );
  }

  async sendHttpRequest(type, url, data, authorizationHeaderString) {
    let headers = {
      "Content-Type": "application/json",
    };
    if (authorizationHeaderString) {
      headers["Authorization"] = authorizationHeaderString;
    }
    let request = {
      method: type,
      headers,
    };
    if (data) {
      request.body = JSON.stringify(data);
    }
    console.log(JSON.stringify(request));
    const response = await fetch(url, request);
    const responseData = await response.json();
    return responseData;
  }

  async sendAuthentication(signatureString, type) {
    let authorizationHeaderString = this.generateAuthorizationString(
      signatureString,
      type
    );
    let url = this.serverUrl + "/api/sessions/this";
    let data = await this.sendPostRequest(url, null, authorizationHeaderString);
    return data;
  }

  generateInitialAuthorizationString() {
    var result =
      "Handle " + 'version="0", ' + 'cnonce="' + this.clientNonceString + '"';
    return result;
  }

  generateAuthorizationString(signatureString, type) {
    let id = this.authInfo.adminIndex + ":" + this.authInfo.adminHandle;
    var result =
      "Handle " +
      'version="0", ' +
      'sessionId="' +
      this.sessionId +
      '", ' +
      'cnonce="' +
      this.clientNonceString +
      '", ' +
      'id="' +
      id +
      '", ' +
      'type="' +
      type +
      '", ' +
      'alg="SHA1", ' +
      'signature="' +
      signatureString +
      '"';
    return result;
  }

  generateExistingSessionAuthorizationString() {
    var result =
      "Handle " + 'version="0", ' + 'sessionId="' + this.sessionId + '"';
    return result;
  }

  async signRsaSha1(jwk, bytes) {
    try {
      const key = await webcrypto.subtle.importKey(
        "jwk",
        jwk,
        {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-1",
        },
        false,
        ["sign"]
      );
      const signature = await webcrypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        key,
        bytes
      );
      const base64Signature = Buffer.from(signature).toString("base64");
      return base64Signature;
    } catch (err) {
      console.error(err);
    }
  }

  async signDsaSha1(jwk, bytes) {
    try {
      const key = await webcrypto.subtle.importKey(
        "jwk",
        jwk,
        {
          name: "NODE-DSA",
          hash: "SHA-1",
        },
        false,
        ["sign"]
      );
      const signature = await webcrypto.subtle.sign("NODE-DSA", key, bytes);
      const base64Signature = Buffer.from(signature).toString("base64");
      return base64Signature;
    } catch (err) {
      console.error(err);
    }
  }

  concatBytes(a, b) {
    return Buffer.concat([a, b]);
  }

  generateClientNonceBytes() {
    return crypto.randomBytes(16);
  }

  async createHandle(handle, values) {
    return await this.createOrUpdateHandle(handle, values, false);
  }

  async updateHandle(handle, values) {
    return await this.createOrUpdateHandle(handle, values, true);
  }

  async createOrUpdateHandle(handle, values, overwrite) {
    if (!this.sessionId) {
      let authResult = await this.authenticate();
    }
    let url = this.serverUrl + "/api/handles/" + handle;
    if (overwrite == false) {
      url += "?overwrite=false";
    }
    let authorizationHeaderString =
      this.generateExistingSessionAuthorizationString();
    let handleRecord = {
      handle,
      values,
    };
    let result = this.sendPutRequest(
      url,
      handleRecord,
      authorizationHeaderString
    );
    return result;
  }

  async getHandle(handle) {
    let url = this.serverUrl + "/api/handles/" + handle;
    let authorizationHeaderString = null;
    if (this.sessionId) {
      authorizationHeaderString =
        this.generateExistingSessionAuthorizationString();
    }
    let result = this.sendGetRequest(url, authorizationHeaderString);
    return result;
  }
}

export async function loadPrivateKey(privateKeyPath) {
  const jwkJson = await fs.readFile(privateKeyPath, "utf8");
  let privateKey = JSON.parse(jwkJson);
  return privateKey;
}

// async function run() {
//   let pathToPrivateKey = "./secrets/admpriv.jwk";
//   let privateKey = await loadPrivateKey(pathToPrivateKey);

//   let serverUrl = "https://85.215.191.151:8000";
//   let auth = {
//     adminIndex: 300,
//     adminHandle: "0.NA/20.500.14528",
//     privateKey: privateKey,
//     mode: "HS_PUBKEY",
//   };

//   let handleRestApi = new HandleRestApi(auth, serverUrl);

//   let handle = "20.500.14528/4z69k-0qh70";
//   let handleValues = [
//     {
//       index: 1,
//       type: "URL",
//       data: {
//         format: "string",
//         value: "https://example.com",
//       },
//     },
//     {
//       index: 100,
//       type: "HS_ADMIN",
//       data: {
//         format: "admin",
//         value: {
//           handle: auth.adminHandle,
//           index: auth.adminIndex,
//           permissions: "011111110011",
//         },
//       },
//     },
//   ];

//   let createResult = await handleRestApi.createHandle(handle, handleValues);
//   console.log(createResult);
//   let createdHandle = await handleRestApi.getHandle(handle);
//   console.log(createdHandle);
// }

// run();
