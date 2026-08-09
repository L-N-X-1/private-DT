# S3 bucket for the manager CA + enrollment password

## Who reads this bucket

Only the cert-issuer service. **Agents never get AWS credentials.** They ask
the issuer, the issuer reads S3, the issuer answers. This matters: if you hand
every endpoint an IAM key so it can pull the enrollment password itself, you
have distributed a long-lived AWS credential to every laptop in the fleet, and
you have made the bucket, not the manager, the thing an attacker goes after.

## Layout

```
s3://acme-wazuh-bootstrap/
  manager/agents-rootCA.pem          <- public CA cert; agents pass this to -v
  manager/enrollment-password.txt    <- the authd shared password
  artifacts/wazuh-agent-4.14.6-1.msi <- optional, if you'd rather not have
  artifacts/Sysmon.zip                  endpoints reach the public internet
  artifacts/sysmonconfig.xml
```

`agents-rootCA.pem` is a **public** certificate — publishing it leaks nothing.
`enrollment-password.txt` is a real secret.

## Create it

```bash
BUCKET=acme-wazuh-bootstrap
REGION=eu-central-1

aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION"

aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws s3api put-bucket-versioning --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

# SSE-KMS with a customer-managed key, so bucket access alone isn't enough --
# the reader also needs kms:Decrypt on the key.
aws kms create-key --description "wazuh-bootstrap" --query KeyMetadata.KeyId --output text
KMS_KEY_ID=<from above>

aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration "{
    \"Rules\": [{
      \"ApplyServerSideEncryptionByDefault\": {
        \"SSEAlgorithm\": \"aws:kms\",
        \"KMSMasterKeyID\": \"$KMS_KEY_ID\"
      },
      \"BucketKeyEnabled\": true
    }]
  }"
```

## Upload

```bash
aws s3 cp agents-rootCA.pem "s3://$BUCKET/manager/agents-rootCA.pem"

# printf, not echo -- echo appends a newline that becomes part of the
# password when the issuer reads it. (The issuer .strip()s it, but don't
# rely on that if you ever read the object with something else.)
printf '%s' 'Enrlp45666215>><,.!' > /tmp/pw.txt
aws s3 cp /tmp/pw.txt "s3://$BUCKET/manager/enrollment-password.txt"
shred -u /tmp/pw.txt
```

## Bucket policy — deny anything not TLS

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::acme-wazuh-bootstrap",
        "arn:aws:s3:::acme-wazuh-bootstrap/*"
      ],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
```

## IAM policy for the issuer — read-only, two objects, nothing else

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadBootstrapSecrets",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": [
        "arn:aws:s3:::acme-wazuh-bootstrap/manager/agents-rootCA.pem",
        "arn:aws:s3:::acme-wazuh-bootstrap/manager/enrollment-password.txt"
      ]
    },
    {
      "Sid": "DecryptWithBootstrapKey",
      "Effect": "Allow",
      "Action": ["kms:Decrypt"],
      "Resource": "arn:aws:kms:eu-central-1:<account-id>:key/<kms-key-id>"
    }
  ]
}
```

Note it grants `GetObject` on two exact keys, not `manager/*`. If someone
later drops a copy of `agents-rootCA.key` in that prefix by mistake, the
issuer still cannot read it.

Your manager is on-prem, so there's no instance role to attach. Options, best
first:

1. **IAM Roles Anywhere** — the issuer host gets an X.509 identity and
   exchanges it for short-lived STS credentials. No static keys on disk.
2. **A dedicated IAM user** with only the policy above, keys in
   `/etc/wazuh-cert-issuer/issuer.env` (mode 640, root:wazuh-issuer), rotated
   on a schedule you actually keep.

Option 2 is what most people do. If you take it, set a calendar reminder for
rotation now, because "we'll rotate it later" is how three-year-old access
keys happen.

## If you really want agents pulling from S3 directly

You asked for the CA pem and password to live in S3, and they do — the
question is only who fetches them. If you specifically need the endpoint to
talk to S3, don't ship it credentials; have the issuer return **presigned
URLs** instead of the file contents:

```python
url = _s3_client().generate_presigned_url(
    "get_object",
    Params={"Bucket": S3_BUCKET, "Key": S3_KEY_MANAGER_CA},
    ExpiresIn=300,
)
```

The agent then `curl`s a URL that works for five minutes and grants nothing
else. Note that a presigned URL for the password object is a bearer token for
that password — it belongs in the response body over TLS, never in a log line
or a command-line argument.
