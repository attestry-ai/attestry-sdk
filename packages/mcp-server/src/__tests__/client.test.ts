import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { getConfig } from "../client.js";

// Pins the default API host (1.1.0: https://attestry.ai, the canonical API
// host and the @attestry/sdk default; 1.0.0 defaulted to attestry.app).

const ORIG_KEY = process.env.ATTESTRY_API_KEY;
const ORIG_URL = process.env.ATTESTRY_API_URL;

function restore(name: "ATTESTRY_API_KEY" | "ATTESTRY_API_URL", value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

beforeEach(() => {
  process.env.ATTESTRY_API_KEY = "test-key-client-config";
  delete process.env.ATTESTRY_API_URL;
});

afterEach(() => {
  restore("ATTESTRY_API_KEY", ORIG_KEY);
  restore("ATTESTRY_API_URL", ORIG_URL);
});

describe("client getConfig — API base URL", () => {
  it("defaults to https://attestry.ai when ATTESTRY_API_URL is unset", () => {
    expect(getConfig().apiUrl).toBe("https://attestry.ai");
  });

  it("defaults to https://attestry.ai when ATTESTRY_API_URL is empty", () => {
    process.env.ATTESTRY_API_URL = "";
    expect(getConfig().apiUrl).toBe("https://attestry.ai");
  });

  it("honours an ATTESTRY_API_URL override and strips one trailing slash", () => {
    process.env.ATTESTRY_API_URL = "https://staging.example.test/";
    expect(getConfig().apiUrl).toBe("https://staging.example.test");
  });

  it("points the missing-key error at the attestry.ai settings page", () => {
    delete process.env.ATTESTRY_API_KEY;
    expect(() => getConfig()).toThrow(/https:\/\/attestry\.ai\/settings/);
  });
});
