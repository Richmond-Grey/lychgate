# Lychgate

Small, readable authentication for Node.js and TypeScript, with security done properly.

> **Status:** pre-1.0 and under active development. Nothing is published to npm yet, and the API
> below is the target, not what exists today.

## Goals

- **Small and readable.** You should be able to read the whole thing and learn from it.
- **Secure by default.** Short-lived JWT access tokens, opaque rotating refresh tokens with reuse
  detection, argon2 password hashing. No custom crypto.
- **Framework- and storage-agnostic core.** Bring your own web framework and database through
  adapters.

## Target API

```ts
const auth = createAuth({
  adapter: prismaAdapter(prisma),
  providers: [credentials(), google({ clientId, clientSecret })],
  roles: { admin: ['*'], user: ['read:own'] },
});

app.use('/auth', auth.router());
app.get('/admin', auth.requireRole('admin'), handler);
```

## Packages

| Package                    | Description                                                        |
| -------------------------- | ------------------------------------------------------------------ |
| `@lychgate/core`           | Types, adapter interface, in-memory adapter, hashing, tokens, RBAC |
| `@lychgate/express`        | Express router and middleware (planned)                            |
| `@lychgate/adapter-prisma` | Prisma storage adapter (planned)                                   |

## Development

Requires Node.js 22.12+ and pnpm.

```powershell
pnpm install
pnpm build
pnpm test
pnpm lint
```

## Security

See [SECURITY.md](./SECURITY.md) for how to report a vulnerability.

## License

[MIT](./LICENSE)
