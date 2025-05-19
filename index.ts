import type { MiddlewareHandler } from "hono";
import { IDocumentLoader, verifyCapabilityInvocation } from "dzcap/invocation-http-signature";
import { HTTPException } from "hono/http-exception";
import { IZcapCapability } from "dzcap/zcap-invocation-request";
import { createDocumentLoader } from "dzcap/document-loader";
import { DID } from "dzcap/did"
import { InvocationJsonVerification } from "dzcap/invocation-json";
import { dataURItoBlob } from "./data-uri.js"

/**
 * parse capability-invocation value out of URLSearchParams (aka query params)
 * @param searchParams 
 * @returns object with capabilityInvocation proof
 */
export async function getInvocationFromSearchParams(searchParams: URLSearchParams) {
  const invocationFromSearchParam = searchParams.get('capability-invocation')
  // if it's a data uri, parse as data uri
  if (invocationFromSearchParam?.startsWith('data:')) {
    const invocationBlob = dataURItoBlob(invocationFromSearchParam)
    const invocationJsonString = await invocationBlob.text()
    const invocationJsonParsed = invocationJsonString && JSON.parse(invocationJsonString)
    if (invocationJsonParsed) {
      return invocationJsonParsed
    }
    throw new Error('unable to parse capability-invocation search param data URI', {
      cause: {
        'capability-invocation': invocationFromSearchParam,
      }
    })
  }
  // try parsing as json
  if (invocationFromSearchParam) {
    try {
      return JSON.parse(invocationFromSearchParam)
    } catch (error) {
      console.debug('error parsing capability-invocation query param value as JSON', error)
    }
  }
  throw new Error(`unable to parse invocation from request`, {
    cause: {
      searchParams,
    }
  })
}

export function createZcapMiddleware(options: {
  expectedTarget?: string,
  expectedAction?: string
  expectedRootCapability?: string | IZcapCapability[]
  documentLoader?: IDocumentLoader
  onVerificationError?: (error: unknown) => void
  resolveRootZcap: (urn: `urn:zcap:root:${string}`) => Promise<{
    controller?: DID,
    "@context": "https://w3id.org/zcap/v1",
    id: string,
    invocationTarget: string,
  }>,
  // if true, the middleware will respond 401 for any requests with no capability-invocation and signature
  required?: boolean,
  trustHeaderXForwardedProto?: boolean
}): MiddlewareHandler {
  const documentLoader = options.documentLoader || createDocumentLoader(async url => {
    if (url.startsWith(`urn:zcap:root:`)) {
      const resolved = await options.resolveRootZcap(url as `urn:zcap:root:${string}`)
      if (!resolved) {
        throw new Error(`resolveRootZcap returned falsy when resolving ${url}`, {
          cause: {
            url,
          }
        })
      }
      return {
        document: resolved,
        documentUrl: url,
      }
    }
    throw new Error(`unable to load document ` + url)
  })
  const middleware: MiddlewareHandler = async (ctx, next) => {
    // const invocation = ctx.req.header('capability-invocation')
    // const encodedCapabilityMatch = invocation?.match(/capability="([^"]+)"/)
    // const encodedCapability = encodedCapabilityMatch?.[1]
    // const capabilityUngzipped = encodedCapability && (await pako.ungzip(Buffer.from(encodedCapability, 'base64url')))
    // const capabilityParsed = capabilityUngzipped && JSON.parse(new TextDecoder().decode(capabilityUngzipped))

    let hasProvenSufficientAuthorization = false

    // check if the invocation is in a ?capability-invocation query param.
    // this is supported to pass around URLs with an invocation to GET them
    const invocationQueryParamValue = ctx.req.query('capability-invocation')
    let searchParamVerification: InvocationJsonVerification | undefined = undefined
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let invocation: any
    if (typeof invocationQueryParamValue === "string") {
      try {
        invocation = await getInvocationFromSearchParams(new URL(ctx.req.raw.url).searchParams)
      } catch (error) {
        throw new HTTPException(400, {
          message: `unable to parse capability-invocation query parameter value. ${error instanceof Error ? error.message : error}`,
          cause: error,
        })
      }
    }
    if (invocation) {
      let invocationTarget
      {
        // invocationTarget is the request url but without the capability-invocation searchParam
        const urlForInvocationTarget = new URL(ctx.req.raw.url)
        urlForInvocationTarget.searchParams.delete('capability-invocation')
        const forwardedProto = ctx.req.header('x-forwarded-proto')
        // @todo - this should only use x-forwarded-proto if configured to trust it
        // similar to 'trust proxy' config in https://expressjs.com/en/guide/behind-proxies.html
        if (forwardedProto && options.trustHeaderXForwardedProto) {
          if (options.trustHeaderXForwardedProto) {
            urlForInvocationTarget.protocol = `${forwardedProto}:`
          } else {
            console.debug(`x-forwarded-proto is set, but options.trustHeaderXForwardedProto is disabled.`)
          }
        }
        invocationTarget = urlForInvocationTarget.toString()
      }
      const verification = await InvocationJsonVerification.from(invocation, {
        documentLoader,
        allowTargetAttenuation: true,
        expectedAction: 'GET',
        expectedTarget: [invocationTarget],
        expectedRootCapability: `urn:zcap:root:${encodeURIComponent(invocationTarget)}`
      })
      if (verification && verification.verified === false) {
        console.debug(`failed to verify invocation JSON`, verification)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        throw new HTTPException(401, {
          message: `capability-invocation query parameter value cannot be verified.`,
        })
      }
      searchParamVerification = verification
      hasProvenSufficientAuthorization = true
    }

    if (ctx.req.header('capability-invocation')) {
      try {
        // zcaps only supported on https urls.
        const assumedInvocationTarget = urlWithProtocol(ctx.req.raw.url, 'https:')
        const expectedTarget = options.expectedTarget ?? assumedInvocationTarget.toString()
        await verifyCapabilityInvocation(ctx.req.raw, {
          expectedTarget,
          expectedAction: options.expectedAction,
          expectedRootCapability: options.expectedRootCapability ?? `urn:zcap:root:${encodeURIComponent(assumedInvocationTarget.toString())}`,
          documentLoader,
        })
        hasProvenSufficientAuthorization = true
      } catch (error) {
        options.onVerificationError?.(error)
        throw new HTTPException(401, {
          message: `unable to verify capability invocation`,
          res: ctx.body(
            JSON.stringify(
              {
                type: 'Error',
                message: `unable to verify capability invocation`,
                cause: {
                  // eslint-disable-next-line @typescript-eslint/no-explicit-any
                  message: (error as any).message,
                  // eslint-disable-next-line @typescript-eslint/no-explicit-any
                  name: (error as any).name,
                },
              },
              undefined,
              2,
            ),
          ),
          cause: error,
        })
      }
    }

    if (options.required && !hasProvenSufficientAuthorization) {
      if (!ctx.req.header('authorization')) {
        const message = `an authorization header is required to access this resource`
        throw new HTTPException(401, {
          message,
          res: new Response(JSON.stringify({message}),{status:401}),
        })
      }
      if (!ctx.req.header('authorization')?.startsWith('Signature ')) {
        throw new HTTPException(401, {
          message: `an HTTP Signature in request authorization header is required to access this resource`,
        })
      }
    }
    return await next()
  }
  return middleware
}

export function urlWithProtocol(url: URL | string, protocol: `${string}:`) {
  const url2 = new URL(url)
  url2.protocol = protocol
  return url2
}

export { createCapabilityInvocationFromRequest } from "dzcap/invocation-http-signature"

export function parseRootZcapUrn(urn: `urn:zcap:root:${string}`) {
  const invocationTarget = decodeURIComponent(urn.split(':').at(3) || '')
  return {
    invocationTarget
  }
}
