// The address `npm run dev -- --host` shares the dev servers on. Its own file so a test can
// read it without starting them.

/** `--host` alone is every interface, `--host <addr>` (or `--host=<addr>`) that one; null when the flag isn't given. */
export function devHost(argv: string[]): string | null {
  const i = argv.findIndex((a) => a === "--host" || a.startsWith("--host="));
  if (i < 0) return null;
  const given = argv[i].startsWith("--host=") ? argv[i].slice("--host=".length) : argv[i + 1];
  return given && !given.startsWith("-") ? given : "0.0.0.0";
}
