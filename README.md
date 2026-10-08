# Popcorn x ZKPassport age demo

Age-only integration prototype: a site asks for `age >= 18`, the user proves it with a ZKPassport proof, and the server re-verifies the raw proof with the ZKPassport SDK against the original query, bound to the browser session. No name, date of birth or ID number is requested.

## Status

- Default mode `passport-only`: real ZKPassport SDK request and QR code, server-side proof re-verification, one-use 5-minute credential tied to the session that asked.
- `popcorn-connected` mode connects a real Popcorn session but does not verify attestation. UI explicitly marks attestation pending. Allocation requires `POPCORN_ALLOCATION_ENABLED=true`.
- `popcorn-attested` mode (opens an encrypted Popcorn browser session) is implemented but fails closed unless Popcorn client credentials and an independent attestation verifier are configured. Not tested end to end.
- Not yet tested with a real passport proof. Success paths are covered by unit tests with stubbed verifiers only.
- Not a compliance claim.

## Run

```
npm ci
PUBLIC_ORIGIN=https://your-host CREDENTIAL_SIGNING_KEY=$(openssl rand -hex 32) npm start
```

Local development (`PUBLIC_ORIGIN` unset, localhost) generates a throwaway signing key. Hosted use requires `CREDENTIAL_SIGNING_KEY`. Sessions are held in memory, so run a single replica.

Environment: `PORT`, `PUBLIC_ORIGIN`, `FLOW_MODE` (`passport-only` | `popcorn-connected` | `popcorn-attested`), `CREDENTIAL_SIGNING_KEY`, and for Popcorn mode `POPCORN_CONTROL_PLANE_URL` (`POPCORN_API_URL` alias), `POPCORN_REGION`, `POPCORN_ALLOCATION_ENABLED`, `POPCORN_CLIENT_ID`, `POPCORN_CLIENT_SECRET`, `ATTESTATION_VERIFIER_URL`, `ATTESTATION_VERIFIER_TOKEN`.

A Dockerfile (Node 22) is included. SDK: `@zkpassport/sdk` 0.17.1.

Local attestation adapter: `ATTESTATION_POLICY_PATH` selects an independently approved policy file. Missing project, zone, instance or service-account policy fails closed. Google signatures/time/nonce/image binding are checked with the reviewed Popcorn OSS verifier; cosign must be installed to check both images against the pinned public key. `attestation-policy.incomplete.json` is deliberately unusable until approved identities are supplied. Current freshness defaults are 300 seconds maximum age and 30 seconds skew; deployment review remains pending. No real attestation has been tested.

## License

MIT. See LICENSE.
