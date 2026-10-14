import { SignJWT } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';
import { AUDIENCE, EMAIL, ISSUER, PASSWORD, SECRET, setup } from '../test-helpers.js';

const FIFTEEN_MINUTES = 15 * 60;

const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
const decodePart = (part: string | undefined) =>
  JSON.parse(Buffer.from(part ?? '', 'base64url').toString()) as Record<string, unknown>;

describe('access tokens', () => {
  let context: ReturnType<typeof setup>;
  let token: string;
  let userId: string;

  beforeEach(async () => {
    context = setup();
    await context.auth.register({ email: EMAIL, password: PASSWORD });
    const session = await context.auth.login({ email: EMAIL, password: PASSWORD });
    token = session.accessToken;
    userId = session.user.id;
  });

  /** Signs a token like ours, with one thing changed, using jose directly. */
  function forge(changes: {
    alg?: string;
    typ?: string;
    iss?: string;
    aud?: string;
    secret?: string;
  }) {
    const issuedAt = Math.floor(context.clock.now().getTime() / 1000);
    return new SignJWT({ roles: ['admin'] })
      .setProtectedHeader({ alg: changes.alg ?? 'HS256', typ: changes.typ ?? 'at+jwt' })
      .setSubject(userId)
      .setIssuer(changes.iss ?? ISSUER)
      .setAudience(changes.aud ?? AUDIENCE)
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + 60)
      .setJti('forged')
      .sign(new TextEncoder().encode(changes.secret ?? SECRET));
  }

  const expectInvalid = (candidate: unknown) =>
    expect(context.auth.verifyAccessToken(candidate as string)).rejects.toMatchObject({
      code: 'INVALID_ACCESS_TOKEN',
    });

  it('accepts a valid token and returns its claims', async () => {
    const claims = await context.auth.verifyAccessToken(token);
    const now = context.clock.now().getTime();

    expect(claims).toEqual({
      userId,
      roles: [],
      tokenId: expect.stringMatching(/^[0-9a-f-]{36}$/) as string,
      issuedAt: new Date(now),
      expiresAt: new Date(now + FIFTEEN_MINUTES * 1000),
    });
  });

  it('carries the expected header and registered claims', () => {
    const [header, payload] = token.split('.');
    expect(decodePart(header)).toEqual({ alg: 'HS256', typ: 'at+jwt' });
    expect(decodePart(payload)).toMatchObject({
      sub: userId,
      iss: ISSUER,
      aud: AUDIENCE,
      roles: [],
    });
  });

  it('allows a few seconds of clock skew, then rejects with ACCESS_TOKEN_EXPIRED', async () => {
    context.clock.advance(FIFTEEN_MINUTES + 4);
    await expect(context.auth.verifyAccessToken(token)).resolves.toBeDefined();

    context.clock.advance(2);
    await expect(context.auth.verifyAccessToken(token)).rejects.toMatchObject({
      code: 'ACCESS_TOKEN_EXPIRED',
    });
  });

  it('rejects a tampered payload', async () => {
    const [header, payload, signature] = token.split('.');
    const escalated = b64({ ...decodePart(payload), roles: ['admin'] });
    await expectInvalid(`${header ?? ''}.${escalated}.${signature ?? ''}`);
  });

  it('rejects a token signed with a different secret', async () => {
    await expectInvalid(await forge({ secret: 'some-other-secret-that-is-also-long-enough-xx' }));
  });

  it('rejects the wrong issuer', async () => {
    await expectInvalid(await forge({ iss: 'https://evil.example' }));
  });

  it('rejects the wrong audience', async () => {
    await expectInvalid(await forge({ aud: 'some-other-api' }));
  });

  it('rejects a JWT that is not typed as an access token', async () => {
    await expectInvalid(await forge({ typ: 'JWT' }));
  });

  it('rejects alg "none"', async () => {
    const [, payload] = token.split('.');
    await expectInvalid(`${b64({ alg: 'none', typ: 'at+jwt' })}.${payload ?? ''}.`);
  });

  it('rejects a validly signed HS512 token (algorithm is pinned to HS256)', async () => {
    await expectInvalid(await forge({ alg: 'HS512' }));
  });

  it.each([
    ['garbage', 'not.a.jwt'],
    ['empty', ''],
    ['a non-string', 42],
  ])('rejects %s', async (_label, candidate) => {
    await expectInvalid(candidate);
  });
});
