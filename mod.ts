import dayjs from "https://esm.sh/dayjs@v1.11.9";
import { FormDataFile } from "../deps.ts";
import { create, type Header } from "https://deno.land/x/djwt@v2.9.1/mod.ts";

type ServiceAccount = {
  type: string;
  project_id: string;
  private_key_id: string;
  private_key: string;
  client_email: string;
  client_id: string;
  auth_uri: string;
  token_uri: string;
  auth_provider_x509_cert_url: string;
  client_x509_cert_url: string;
  universe_domain: string;
};

function str2ab(value: string) {
  const buf = new ArrayBuffer(value.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, len = value.length; i < len; i++) {
    bufView[i] = value.charCodeAt(i);
  }
  return buf;
}

export class GoogleStorage {
  private sa: ServiceAccount;
  private scope: string;
  private bucketName: string;
  private region: string;

  constructor(
    sa: ServiceAccount,
    scope: string,
    bucket: { name: string; region: string }
  ) {
    this.sa = sa;
    this.scope = scope;
    this.bucketName = bucket.name;
    this.region = bucket.region;
  }

  private getPrivateKey(extractable = true) {
    // fetch the part of the PEM string between header and footer
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----";
    const pemContents = this.sa.private_key
      .replace(pemHeader, "")
      .replace(pemFooter, "");
    // base64 decode the string to get the binary data
    const binaryDerString = atob(pemContents);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

    return crypto.subtle.importKey(
      "pkcs8",
      binaryDer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      },
      extractable,
      ["sign"]
    );
  }

  private async getToken() {
    const payload = {
      iss: this.sa.client_email,
      sub: this.sa.client_email,
      scope: this.scope,
      aud: this.sa.token_uri,
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour expiration
      iat: Math.floor(Date.now() / 1000),
    };

    const key = await this.getPrivateKey();
    const header: Header = {
      alg: "RS256",
      typ: "JWT",
      kid: this.sa.private_key_id,
    };

    const jwt = await create(header, payload, key);

    // Send a POST request to get access token
    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: jwt,
      }),
    });

    const result = await response.json();

    return {
      access_token: result.access_token,
      expires_in: result.expires_in,
      token_type: result.token_type,
    };
  }

  private async signWithRSA(data: string) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const key = await this.getPrivateKey();
    const signatureBuffer = await crypto.subtle.sign(
      {
        name: "RSASSA-PKCS1-v1_5",
      },
      key,
      dataBuffer
    );
    const signatureArray = new Uint8Array(signatureBuffer);
    return Array.from(signatureArray, (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");
  }

  private async createSHA256Hash(input: string) {
    const data = new TextEncoder().encode(input);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    return hashHex;
  }

  public async upload(file: FormDataFile, path: string) {
    if (!file) {
      throw new Error("No file!");
    }
    const token = await this.getToken();
    const url = `https://storage.googleapis.com/upload/storage/v1/b/${this.bucketName}/o?uploadType=media&name=${path}`;
    return fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token.access_token}`,
        "Content-Type": file.contentType,
        "Content-Length": `${file.content?.length ?? 0}`,
      },
      body: file.content,
    }).then((res) => res.json());
  }

  public async getSignedUrl(
    objectName: string,
    expiration = 604800,
    httpMethod = "GET",
    queryParameters: any = {},
    headers: any = {}
  ) {
    if (expiration > 604800) {
      console.log(
        "Expiration Time can't be longer than 604800 seconds (7 days)."
      );
      throw new Error(
        "Expiration Time can't be longer than 604800 seconds (7 days)."
      );
    }

    // Escape object name
    const escapedObjectName = encodeURIComponent(objectName);

    const canonicalUri = `/${escapedObjectName}`;

    const now = dayjs();
    const requestTimestamp = now.format("YYYYMMDD[T]HHmmss[Z]");
    const datestamp = requestTimestamp.slice(0, 8);

    const clientEmail = this.sa.client_email;
    const credentialScope = `${datestamp}/${this.region}/storage/goog4_request`;
    const credential = `${clientEmail}/${credentialScope}`;

    if (!headers) {
      headers = {};
    }
    const host = `${this.bucketName}.storage.googleapis.com`;
    headers["host"] = host;

    let canonicalHeaders = "";
    const orderedHeaders = Object.fromEntries(
      Object.entries(headers).sort((a, b) => a[0].localeCompare(b[0]))
    );
    for (const [k, v] of Object.entries(orderedHeaders)) {
      const lowerK = k.toLowerCase();
      const stripV = v.toLowerCase();
      canonicalHeaders += `${lowerK}:${stripV}\n`;
    }

    let signedHeaders = "";
    for (const [k] of Object.entries(orderedHeaders)) {
      const lowerK = k.toLowerCase();
      signedHeaders += `${lowerK};`;
    }
    signedHeaders = signedHeaders.slice(0, -1); // remove trailing ';'

    if (!queryParameters) {
      queryParameters = {};
    }
    queryParameters["X-Goog-Algorithm"] = "GOOG4-RSA-SHA256";
    queryParameters["X-Goog-Credential"] = credential;
    queryParameters["X-Goog-Date"] = requestTimestamp;
    queryParameters["X-Goog-Expires"] = expiration;
    queryParameters["X-Goog-SignedHeaders"] = signedHeaders;

    const canonicalQueryString = Object.entries(queryParameters)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");

    const canonicalRequest = [
      httpMethod,
      canonicalUri,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      "UNSIGNED-PAYLOAD",
    ].join("\n");

    const canonicalRequestHash = await this.createSHA256Hash(canonicalRequest);

    const stringToSign = [
      "GOOG4-RSA-SHA256",
      requestTimestamp,
      credentialScope,
      canonicalRequestHash,
    ].join("\n");

    const signature = await this.signWithRSA(stringToSign);

    const schemeAndHost = "https://" + host;
    const signedUrl = `${schemeAndHost}${canonicalUri}?${canonicalQueryString}&x-goog-signature=${signature}`;

    return signedUrl;
  }
}
