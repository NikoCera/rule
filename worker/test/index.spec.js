import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

const RULE_URL =
  "https://example.com/auth/test-download-token/Surge/AIGC/AIGC.list";

describe("Rule worker", () => {
  it("rejects unauthenticated requests", async () => {
    const response = await exports.default.fetch(
      "https://example.com/Surge/AIGC/AIGC.list",
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("serves committed rule assets with a path token", async () => {
    const response = await exports.default.fetch(RULE_URL);

    expect(response.status).toBe(200);
    expect(await response.text()).toContain("DOMAIN");
    expect(response.headers.get("Cache-Control")).toContain("private");
  });

  it("rejects the legacy query token", async () => {
    const response = await exports.default.fetch(
      "https://example.com/Surge/AIGC/AIGC.list?token=test-download-token",
    );

    expect(response.status).toBe(401);
  });

  it("rejects an incorrect path token", async () => {
    const response = await exports.default.fetch(
      "https://example.com/auth/wrong-token/Surge/AIGC/AIGC.list",
    );

    expect(response.status).toBe(401);
  });

  it("accepts a bearer token and keeps unknown assets unavailable", async () => {
    const response = await exports.default.fetch(
      new Request("https://example.com/Clash/missing.list", {
        headers: { Authorization: "Bearer test-download-token" },
      }),
    );

    expect(response.status).toBe(404);
  });

  it("rewrites private GitHub self-references inside modules", async () => {
    const response = await exports.default.fetch(
      "https://example.com/auth/test-download-token/Surge/Module/%E7%BD%91%E6%98%93%E4%BA%91%E9%9F%B3%E4%B9%90%E5%8E%BB%E5%B9%BF%E5%91%8A%20fix@myself.sgmodule",
    );
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).not.toContain("raw.githubusercontent.com/NikoCera/rule");
    expect(body).toContain(
      "https://example.com/auth/test-download-token/Surge/Script/netease.adblock.surge.js",
    );
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("allows HEAD but rejects mutating methods", async () => {
    const headResponse = await exports.default.fetch(
      new Request(RULE_URL, { method: "HEAD" }),
    );
    const postResponse = await exports.default.fetch(
      new Request(RULE_URL, { method: "POST" }),
    );

    expect(headResponse.status).toBe(200);
    expect(await headResponse.text()).toBe("");
    expect(postResponse.status).toBe(405);
  });
});
