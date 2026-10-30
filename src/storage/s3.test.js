import assert from "node:assert/strict";
import { test } from "node:test";

import { ObjectStorage, authorization } from "./s3.js";

// L'exemple publié par AWS (« GET Object », documentation SigV4 de S3) : si notre
// signature diffère d'un octet de la leur, chaque envoi rendra 403.
test("signe exactement comme l'exemple de référence AWS", () => {
  const header = authorization(
    { accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", region: "us-east-1" },
    "GET",
    "https://examplebucket.s3.amazonaws.com/test.txt",
    {
      Host: "examplebucket.s3.amazonaws.com",
      Range: "bytes=0-9",
      "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "x-amz-date": "20130524T000000Z",
    },
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
  assert.equal(
    header,
    "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
      "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
      "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
  );
});

test("`?uploads` se canonise en `uploads=` (initiation multipart)", () => {
  const creds = { accessKeyId: "a", secretAccessKey: "b", region: "r" };
  const headers = { Host: "h", "x-amz-date": "20260101T000000Z" };
  assert.equal(authorization(creds, "POST", "https://h/b/k?uploads", headers, "x"), authorization(creds, "POST", "https://h/b/k?uploads=", headers, "x"));
});

test("l'adresse du dépôt suit celle des agents PHP", () => {
  assert.equal(new ObjectStorage("backblaze_b2", { key_id: "k", app_key: "s", bucket_name: "b", region: "eu-central-003" }).objectUrl("backups/x"), "https://s3.eu-central-003.backblazeb2.com/b/backups/x");
  assert.equal(new ObjectStorage("backblaze_b2", { key_id: "k", app_key: "s", bucket_name: "b", endpoint: "http://slim-s3:9000/" }).objectUrl("/a"), "http://slim-s3:9000/b/a");
  assert.throws(() => new ObjectStorage("backblaze_b2", { key_id: "", app_key: "s", bucket_name: "b" }), /Cloud credentials not configured/);
});
