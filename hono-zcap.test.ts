import { test } from 'node:test'
import { Hono, } from "hono"
import * as honoZcap from "./index.js"
import { createRequestForCapabilityInvocation } from 'dzcap/zcap-invocation-request'
import { Ed25519Signer } from "@did.coop/did-key-ed25519"
import * as assert from 'node:assert'
import { createCapabilityInvocationFromRequest, IDocumentLoader, MissingRequiredHeaderError, verifyCapabilityInvocation } from 'dzcap/invocation-http-signature'
import { HTTPException
} from 'hono/http-exception'
import { DID, getDidForDidUri } from 'dzcap/did'

await test('hono-zcap', async (t) => {
  await t.test('accepts valid caps', async () => {
    // alice has this key that will invoke the capability to sign the invocation
    const aliceKey = await Ed25519Signer.generate()

    // create a hono app using hono-zcap
    const app = new Hono()
      .use(honoZcap.createZcapMiddleware({
        expectedAction: 'get',
        resolveRootZcap: async (urn: `urn:zcap:root:${string}`) => {
          const invocationTarget = decodeURIComponent(urn.split(':').at(3) || '')
          const aliceKeyDid: DID = getDidForDidUri(aliceKey.id)
          return {
            "@context": "https://w3id.org/zcap/v1",
            id: urn,
            controller: aliceKeyDid,
            invocationTarget,
          }
        }
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
      
    // we will invoke a route that responds with the parsed invocation
    const invocationTargetUrl = new URL('https://test.example/capability-invocation')

    // create request with valid invocation
    const invocationAction = 'get'
    const invocationSigner = aliceKey
    const request = new Request(invocationTargetUrl, {
      ...await createRequestForCapabilityInvocation(invocationTargetUrl, {
        action: invocationAction,
        invocationSigner,
        method: 'GET',
      }),
    })

    // send request w/ invocation to server to get response.
    const response = await app.request(request)
    assert.equal(response.status, 200)
    const responseObject = await response.json()
    
    // the responseObject should be the invocation as parsed by the server
    assert.ok(typeof responseObject === 'object' && responseObject)
    assert.ok('action' in responseObject)
    assert.equal(responseObject.action, invocationAction)
    assert.ok('capability' in responseObject && typeof responseObject.capability === 'object' && responseObject.capability)
    assert.ok('id' in responseObject.capability)
    // capability id should be root zcap of url.
    // (because we are invoking the root zcap, not a delegated one)
    assert.equal(responseObject.capability.id, `urn:zcap:root:${encodeURIComponent(invocationTargetUrl.toString())}`)
    
  })

  await t.test('responds 401 to requests with invalid syntax or insufficient proof of authorization', async (t) => {
    // alice has this key that will invoke the capability to sign the invocation
    const aliceKey = await Ed25519Signer.generate()

    const app = new Hono()
    .use(honoZcap.createZcapMiddleware({
      expectedAction: 'get',
      resolveRootZcap: async (urn: `urn:zcap:root:${string}`) => {
        const invocationTarget = decodeURIComponent(urn.split(':').at(3) || '')
        const aliceKeyDid: `did:key:${string}` = getDidForDidUri(aliceKey.id) as `did:key:${string}`
        return {
          "@context": "https://w3id.org/zcap/v1",
          id: urn,
          controller: aliceKeyDid,
          invocationTarget,
        }
      }
    }))
    .get('/capability-invocation', async c => {
      const invocation = await createCapabilityInvocationFromRequest(c.req.raw)
      if (invocation instanceof Error) {
        throw new HTTPException(500, {
          message: 'unable to parse invocation from request',
          cause: invocation,
        })
      }
      return c.json(invocation)
    })
    // create capability that will be invoked
    const invocationTargetUrl = new URL('http://test.example/capability-invocation')
 
    // create request with valid invocation
    const invocationAction = 'get'
    const invocationSigner = aliceKey

    // loop through example bad headers, testing that each one is invalid in the same way
    const exampleBadHeaders = [
      {
        'capability-invocation': 'zcap foooasdfasd',
      },
      {
        'capability-invocation': 'zcap foooasdfasd',
        authorization: `Signature`,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        check(error: any) {
          assert.equal(error.cause.message, 'keyId was not specified')
        }
      },
      {
        'capability-invocation': 'zcap foooasdfasd',
        authorization: 'Signature keyId="did:key:z6MkjHag5zBaPWTEKhJGAYYcixW9EU9d9HdzsGsGUCCnqPrE#z6MkjHag5zBaPWTEKhJGAYYcixW9EU9d9HdzsGsGUCCnqPrE"',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        check(error: any) {
          assert.equal(error.cause.message, 'signature was not specified')
        }
      },
      {
        'capability-invocation': 'zcap foooasdfasd',
        authorization: 'Signature keyId="did:key:z6MkjHag5zBaPWTEKhJGAYYcixW9EU9d9HdzsGsGUCCnqPrE#z6MkjHag5zBaPWTEKhJGAYYcixW9EU9d9HdzsGsGUCCnqPrE",signature="H0kDXXNg32wSKfwGW2GyshH8Yl9b7CD/Z9ffA89uFOkPdBILfjtn6teQd+WkaMYAE12nLMintL9eyeIRZR+gCQ==",created="1731372291",expires="1731372891"',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        check(error: any) {
          assert.equal(error.cause.message, 'The signature has expired.')
        }
      },
      {
        'capability-invocation': 'zcap foooasdfasd',
        authorization: 'Signature keyId="did:key:z6MkkFCK2HADzAt2a4seYPrTPPfm1cCWGbHWSyYyrcBipKan#z6MkkFCK2HADzAt2a4seYPrTPPfm1cCWGbHWSyYyrcBipKan",headers="(key-id) (created) (expires) (request-target) host capability-invocation",signature="bgDiSPJcjROkS3hO9v6cDXiL8K9tAE9q43gGz4QMxnz2FIyhHjRlAVq3PF49fdoSQUWFliUy8ukWDgDvJkQtDw=="',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        check(error: any) {
          assert.equal(error.cause.message, 'created was not in the request')
        }
      },
      {
        'capability-invocation': 'zcap foooasdfasd',
        authorization: 'Signature keyId="did:key:z6MksororhyFwsaeXw812F4hScpeucoxanBTeLRdAPQoEqAW#z6MksororhyFwsaeXw812F4hScpeucoxanBTeLRdAPQoEqAW",headers="(key-id) (created) (expires) (request-target) host capability-invocation",signature="BRwZMg6LbsJ9Qm1yUa25aqb6BpyTU8WPQX1343arV2929sz0FRTAIMovtzKyASDrAxug6deumkYynmH3KtOrAw==",created="1731372941"',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        check(error: any) {
          assert.equal(error.cause.message, 'expires was not in the request')
        }
      },
      {
        'capability-invocation': 'zcap foooasdfasd',
        authorization: 'Signature keyId="did:key:z6Mksdm6Zc2UMrVkzBZUnFcJPSqtnVTNFCeLXWjjcft2JUD7#z6Mksdm6Zc2UMrVkzBZUnFcJPSqtnVTNFCeLXWjjcft2JUD7",headers="(key-id) (created) (expires) (request-target) host capability-invocation",signature="oarrWFs+8PL+BgPuXer0oga/aOr+1/XYfuFSoaBNtiSF6V5zs8zXsJcHyyCFO+paaaM0G5ltQGYKijqV5a95Bw==",created="1731372996",expires="1731373596"',
      }
    ]

    for (const headers of exampleBadHeaders) {
      await test(`rejects headers ${JSON.stringify(headers)}`, async (t) => {
        const headersForRequest: Record<string,string> = {}
        if (headers.authorization) {
          headersForRequest.authorization = headers.authorization
        }
        if (headers['capability-invocation']) {
          headersForRequest['capability-invocation'] = headers['capability-invocation']
        }
        const request = new Request(invocationTargetUrl, {
          headers: headersForRequest
        })
          // send request w/ invocation to server to get response.
        const response = await app.request(request)
        assert.equal(response.status, 401)
        const responseObject = await response.json()
        headers.check?.(responseObject)
      })
    }

  })


})
