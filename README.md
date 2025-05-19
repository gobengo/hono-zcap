# hono-zcap

[Hono][hono] authorization middleware that verifies
[zcap][Authorization Capabilities for Linked Data v0.3]
invocations.

## Usage

```typescript
import { Hono } from "hono"
import { HTTPException } from "hono/http-exception"
import * as honoZcap from "hono-zcap"
import { Ed25519VerificationKey2020 } from "hono-zcap"

/**
 * In this example, this key will be the controller of
 * every capability. i.e. it can sign zcaps to authorize invocations.
 * This will generate a new keypair each run.
 * In production, you probably want to load some configuration and build a keyPair object that uses the same keypair each time.
 */
const superUserKey = await Ed25519VerificationKey2020.generate()

/*
 * invocations invoke capabilities.
 * capabilities without parents are 'root capabilities',
 * given a root zcap urn, return an object describing it, including any dids that controll it (i.e. that can delegate authority to invoke it)
 */
async function resolveRootZcap(urn: `urn:zcap:root:${string}`) {
  const invocationTarget = decodeURIComponent(urn.split(':').at(3) || '')
  return {
    "@context": "https://w3id.org/zcap/v1" as const,
    id: urn,
    controller: honoZcap.getDidForDidUri(superUserKey.id),
    invocationTarget,
  }
}

const app = new Hono
  .use(honoZcap.createZcapMiddleware({
    expectedAction: 'get',
    resolveRootZcap,
  }))
  .get('/capability-invocation', async c => {
    const invocation = await honoZcap.createCapabilityInvocationFromRequest(c.req.raw)
    if (invocation instanceof Error) {
      throw new HTTPException(500, {
        message: 'unable to parse invocation from request',
        cause: invocation,
      })
    }
    return c.json(invocation)
  })

export default app
```

[hono]: https://hono.dev/
[Authorization Capabilities for Linked Data v0.3]: https://w3c-ccg.github.io/zcap-spec/
