# Lychgate: project context for Claude

Lychgate is an open-source authentication package for Node.js/TypeScript, published under the npm
scope `@lychgate` (the org already exists). It is a personal portfolio project.

**The angle:** small, readable, easy to learn from, with security done properly. Prefer clarity over
cleverness; code should be readable as teaching material.

## How to work in this repo

- **One phase at a time.** Finish a phase, then stop, summarize, and wait for the maintainer's
  go-ahead before starting the next one. Explain decisions briefly as you go.
- **Every phase ends with passing tests and a git commit** using Conventional Commits
  (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`, `ci:`; scope optional, e.g.
  `feat(core): ...`).
- **Do not add Claude as a co-author** on commits (no `Co-Authored-By` trailer).
- **The maintainer uses Windows + PowerShell.** Every command you suggest or put in docs must be
  PowerShell-compatible (no `&&` chaining in PowerShell 5.1, no `rm -rf`, no `VAR=x cmd`). npm
  scripts must also work cross-platform.
- **Do not publish anything to npm** until Phase 8.

## Commands

```powershell
pnpm install     # install all workspace deps
pnpm build       # tsup build of every package (ESM + CJS + .d.ts)
pnpm test        # Vitest across all packages (root config uses `projects`)
pnpm lint        # ESLint (type-checked) + Prettier check
pnpm typecheck   # tsc --noEmit in every package
pnpm format      # Prettier write
```

## Decisions already made

- **Monorepo** with pnpm workspaces (`packages/*`, `examples/*`).
- **TypeScript strict**, ESM + CJS builds via **tsup**, tests with **Vitest**.
  - TypeScript is pinned to **6.0.x** because typescript-eslint supports `<6.1.0`. Do not bump to
    TS 7 until typescript-eslint and tsup support it.
- **Access token:** short-lived JWT via `jose`.
- **Refresh token:** opaque, stored **hashed** via the adapter, **rotated on every use**, with
  **reuse detection**: presenting an already-used refresh token revokes the whole token family.
- **Passwords:** argon2. **Never write custom crypto**; use vetted libraries and `node:crypto`.
- **Token delivery:** tokens are returned in the response body, with optional httpOnly cookie
  delivery (configurable).
- **Core is framework-agnostic and storage-agnostic:** `@lychgate/core` must have no Express, Prisma,
  or other DB/framework imports.
- **Out of scope for v1 (these are v2):** password reset, email verification, rate limiting, magic
  links, 2FA, passkeys, Next.js adapter.
- **Package metadata:** every publishable package is public on npm with
  `"publishConfig": { "access": "public" }`, MIT license, starting version `0.1.0`.

## Packages

| Package                    | Contents                                                           |
| -------------------------- | ------------------------------------------------------------------ |
| `@lychgate/core`           | Types, adapter interface, in-memory adapter, hashing, tokens, RBAC |
| `@lychgate/express`        | Router and middleware                                              |
| `@lychgate/adapter-prisma` | Prisma storage adapter                                             |

Google OAuth arrives later as a provider.

## Target API (v1)

```ts
const auth = createAuth({
  adapter: prismaAdapter(prisma),
  providers: [credentials(), google({ clientId, clientSecret })],
  roles: { admin: ['*'], user: ['read:own'] },
});
app.use('/auth', auth.router());
app.get('/admin', auth.requireRole('admin'), handler);
```

## Build phases

1. **Foundation:** monorepo, TS config, ESLint/Prettier, Vitest, GitHub Actions CI, MIT license,
   README stub, SECURITY.md (pre-1.0 note). Placeholder `@lychgate/core` with one test. ✅
2. **Core:** types, adapter interface, in-memory adapter, password hashing.
3. **Auth flows:** register/login, then access and refresh tokens with rotation and reuse detection.
4. **RBAC:** roles, permissions, guards.
5. **Express package**, plus an example app.
6. **Prisma adapter**, tested against a real DB.
7. **Google OAuth.**
8. **Polish:** security docs, README with demo GIF, Changesets setup, publish with provenance from
   GitHub Actions.

## Conventions

- Package layout: `packages/<name>/{src, package.json, tsconfig.json, tsup.config.ts,
vitest.config.ts}`. Tests live next to source as `*.test.ts`.
- Each package's `package.json` has a dual `exports` map (`import` → `.js`/`.d.ts`, `require` →
  `.cjs`/`.d.cts`), `"type": "module"`, `"files": ["dist"]`, and `"sideEffects": false`.
- Relative imports in source use the `.js` extension (NodeNext resolution).
- Use `import type` for type-only imports (enforced by ESLint).
- Shared compiler options live in `tsconfig.base.json`; packages extend it.
- Line endings are LF (enforced by `.gitattributes`, `.editorconfig`, and Prettier).
