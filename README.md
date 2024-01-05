# google_cloud_storage

Deno Library to upload files to GCS and obtain signed url

### Usage

```ts
import { GoogleStorage } from "https://deno.land/x/google_cloud_storage@{version}/mod.ts";
import serviceAccount from "service_account.json" assert { type: "json" };

const storage = new GoogleStorage(
  serviceAccount,
  "https://www.googleapis.com/auth/devstorage.full_control",
  {
    name: BUCKET_NAME,
    region: "asia-northeast3",
  }
);

const result = await storage.upload(file, path);
const signedUrl = await storage.getSignedUrl(objectName, 900);
```

### Example content of Google service accounts credentials JSON file. Get this from Google's admin console.

```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "01234567890",
  "private_key": "-----BEGIN PRIVATE KEY-----YOUR PRIVATE KEY-----END PRIVATE KEY-----",
  "client_email": "service-acct@<your-poject-id>.iam.gserviceaccount.com",
  "client_id": "01234567890",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/service-acct%40your-service-account-name.iam.gserviceaccount.com"
}
```
