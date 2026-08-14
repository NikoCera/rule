import { mkdir, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const workerDir = resolve(scriptDir, "..");
const repositoryDir = resolve(workerDir, "..");
const assetDir = resolve(workerDir, "public");

if (dirname(assetDir) !== workerDir) {
  throw new Error("Refusing to build outside the Worker directory");
}

await rm(assetDir, { recursive: true, force: true });
await mkdir(assetDir, { recursive: true });

const archive = spawnSync(
  "git",
  ["-C", repositoryDir, "archive", "--format=tar", "HEAD", "Surge", "Clash"],
  { encoding: null, maxBuffer: 32 * 1024 * 1024 },
);

if (archive.status !== 0) {
  throw new Error(
    `git archive failed: ${archive.stderr?.toString().trim() || "unknown error"}`,
  );
}

const extract = spawnSync("tar", ["-xf", "-", "-C", assetDir], {
  input: archive.stdout,
  encoding: null,
  maxBuffer: 32 * 1024 * 1024,
});

if (extract.status !== 0) {
  throw new Error(
    `tar extraction failed: ${extract.stderr?.toString().trim() || "unknown error"}`,
  );
}

console.log("Built committed Surge and Clash assets from HEAD.");
