/**
 * Example custom login handler.
 *
 * Bound into a deployment with:
 *
 *   strategies:
 *     - name: pictures
 *       type: custom
 *       handler: /app/custom/custom-login.mjs
 *       timeout_ms: 5000
 *       options:
 *         profileUrl: https://profiles.example.com/lookup
 *         tier: pictures
 *       jwt: { algorithm: RS256, issuer: token-weaver, ttl: 3600 }
 *
 * Contract:
 *   return claims (or { claims })  -> minted into the token by Token Weaver
 *   return null / undefined        -> 401
 *   throw with a numeric .status   -> that status (use the injected HttpError)
 *   throw anything else            -> 500, logged; never reported as bad credentials
 *   exceed timeout_ms              -> 503
 *
 * The module runs IN-PROCESS with the service's privileges: it is deployment code, not user
 * input. Mounted anywhere under the app directory it can also import Token Weaver's own
 * dependencies (jose, yaml, zod, ...) directly, since node resolves from there.
 */

/**
 * @param {object} ctx
 * @param {{ method: string, path: string, headers: Record<string, unknown>, query: Record<string, unknown>, body: unknown, ip?: string }} ctx.request
 *   The request, shaped exactly as the `$.request.*` mapping expressions see it.
 * @param {Record<string, unknown>} ctx.options   `options` from the strategy config.
 * @param {{ info: Function, warn: Function, error: Function, debug: Function }} ctx.logger
 * @param {Function} ctx.httpRequest             Token Weaver's fetch wrapper (logging, timeouts).
 * @param {new (status: number, message: string) => Error} ctx.HttpError
 */
export default async function authenticate({ request, options, logger, httpRequest, HttpError }) {
  const { username, passcode } = request.body ?? {};

  // Reject with the status that fits. A bare `return null` is a 401.
  if (typeof username !== 'string' || typeof passcode !== 'string') {
    throw new HttpError(400, 'username and passcode are required');
  }

  // Anything a login needs: several upstreams, a bespoke signature scheme, project rules.
  const response = await httpRequest(String(options.profileUrl), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, passcode }),
    timeoutMs: 3000,
  });

  if (response.status === 401 || response.status === 403) {
    logger.info('custom login rejected by profile service', { username });
    return null; // -> 401
  }
  if (!response.ok) {
    // Distinguish "upstream is broken" from "credentials are wrong".
    throw new HttpError(503, 'Profile service unavailable');
  }

  const profile = await response.json();

  // Only what is returned here is minted. Keep access-control claims deliberate: never echo an
  // upstream's permissions straight through unless that is genuinely what you mean.
  return {
    sub: profile.id,
    tier: options.tier,
    routes: {
      whitelist: ['ipb/v1/login', 'ipb/v1/getPlayerState'],
      blacklist: [],
    },
  };
}
