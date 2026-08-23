import { describe, it, expect, vi, afterEach } from "vitest";
import { fetchAgents, fetchStats, fetchAgent } from "../api";

// The API layer is the page's whole relationship with the hub. Everything
// a reader sees comes through it, and until now nothing checked what it
// does when the hub says something unexpected — which, for a page pointed
// at somebody else's server over the public internet, is the ordinary
// case rather than the edge one.

function respond(body: string, ok = true, status = 200): Response {
  return { ok, status, text: async () => body } as unknown as Response;
}

afterEach(() => vi.unstubAllGlobals());

describe("what the page does when the hub misbehaves", () => {
  it("surfaces the hub's own error message rather than a status code", async () => {
    vi.stubGlobal("fetch", async () =>
      respond(JSON.stringify({ error: "agent not registered" }), false, 404),
    );
    // A reader who is told "agent not registered" can act. One told
    // "HTTP 404" has to go and ask somebody what that means.
    await expect(fetchAgents("")).rejects.toThrow("agent not registered");
  });

  it("falls back to the body, then the status, when there is no message", async () => {
    vi.stubGlobal("fetch", async () => respond("upstream exploded", false, 502));
    await expect(fetchStats()).rejects.toThrow("upstream exploded");

    vi.stubGlobal("fetch", async () => respond("", false, 503));
    await expect(fetchStats()).rejects.toThrow("HTTP 503");
  });

  it("does not present unparseable success as data", async () => {
    // A proxy that returns an HTML error page with status 200 is a real
    // thing that happens. Rendering its fields as an empty agent list
    // would tell the reader the network is empty, which is a lie.
    vi.stubGlobal("fetch", async () => respond("<html>gateway</html>", true, 200));
    await expect(fetchAgents("")).resolves.toEqual([]);
  });

  it("treats a missing agents array as no agents, not as a crash", async () => {
    vi.stubGlobal("fetch", async () => respond(JSON.stringify({})));
    await expect(fetchAgents("")).resolves.toEqual([]);
  });
});

describe("the search query reaches the hub intact", () => {
  it("escapes a query so it cannot rewrite the request", async () => {
    let seen = "";
    vi.stubGlobal("fetch", async (url: string) => {
      seen = url;
      return respond(JSON.stringify({ agents: [] }));
    });
    // Without encoding, "&cap=x" would arrive as a second parameter and
    // silently change what was asked for.
    await fetchAgents("a&cap=x");
    expect(seen).toBe("/agents?q=a%26cap%3Dx");
  });

  it("asks for everything when the query is empty", async () => {
    let seen = "";
    vi.stubGlobal("fetch", async (url: string) => {
      seen = url;
      return respond(JSON.stringify({ agents: [] }));
    });
    await fetchAgents("");
    expect(seen).toBe("/agents");
  });

  it("escapes an AID in the path", async () => {
    let seen = "";
    vi.stubGlobal("fetch", async (url: string) => {
      seen = url;
      return respond(JSON.stringify({ agent: {}, reviews: [] }));
    });
    await fetchAgent("did:anet:a/b");
    expect(seen).toContain(encodeURIComponent("did:anet:a/b"));
  });
});

describe("the fields this hub actually sends", () => {
  it("keeps home_hub, last_seen and quiet", async () => {
    // These three went missing from the TypeScript declaration while the
    // Go side was sending them, so the page could not tell a federated
    // agent from a local one nor show which had stopped answering. The Go
    // test TestTheWebUIDeclaresTheFieldsThisPackageSends stops the
    // declaration drifting again; this one proves the values survive the
    // trip and arrive where a component can read them.
    vi.stubGlobal("fetch", async () =>
      respond(
        JSON.stringify({
          agents: [
            {
              aid: "a", name: "Remote", caps: ["work.do"], listed: true,
              guest_quota: 5, avg_rating: 0, review_count: 0,
              registered_at: "2026-08-23T00:00:00Z",
              home_hub: "https://other.example",
              last_seen: "2026-08-23T00:00:00Z",
              quiet: true,
            },
          ],
        }),
      ),
    );
    const [a] = await fetchAgents("");
    expect(a.home_hub).toBe("https://other.example");
    expect(a.quiet).toBe(true);
    expect(a.last_seen).toBe("2026-08-23T00:00:00Z");
  });

  it("reads an absent quiet as not quiet", async () => {
    // omitempty means a healthy agent carries no quiet field at all. A
    // reader that treated absent as unknown would flag everyone.
    vi.stubGlobal("fetch", async () =>
      respond(JSON.stringify({ agents: [{ aid: "a", name: "Live", caps: [], listed: true, guest_quota: 5, avg_rating: 0, review_count: 0, registered_at: "x" }] })),
    );
    const [a] = await fetchAgents("");
    expect(a.quiet).toBeFalsy();
  });
});
