export class StreamFlowClient {
  constructor(baseUrl, options = {}) {
    this.baseUrl = String(baseUrl).replace(/\/+$/, "");
    this.apiPassword = options.apiPassword || "";
    this.proxyAuth = options.proxyAuth || "";
  }

  async health() {
    return this.#json("/health");
  }

  async metrics(password) {
    const headers = password ? { "X-Metrics-Password": password } : {};
    const res = await fetch(`${this.baseUrl}/metrics`, { headers });
    if (!res.ok) throw new Error(`stream-flow metrics failed: ${res.status}`);
    return res.text();
  }

  async proxify(urls, options = {}) {
    const body = new URLSearchParams();
    for (const url of Array.isArray(urls) ? urls : [urls]) body.append("url", url);
    if (options.token) body.set("token", options.token);
    const res = await fetch(`${this.baseUrl}/v0/proxy`, {
      method: "POST",
      headers: this.#headers({ "content-type": "application/x-www-form-urlencoded" }),
      body
    });
    if (!res.ok) throw new Error(`stream-flow proxify failed: ${res.status}`);
    return res.json();
  }

  storeAddonManifest(store = "rd") {
    return `${this.baseUrl}/stremio/store/${encodeURIComponent(store)}/manifest.json`;
  }

  wrapAddonManifest() {
    return `${this.baseUrl}/stremio/wrap/manifest.json`;
  }

  async #json(path) {
    const res = await fetch(`${this.baseUrl}${path}`, { headers: this.#headers() });
    if (!res.ok) throw new Error(`stream-flow request failed: ${res.status}`);
    return res.json();
  }

  #headers(extra = {}) {
    const headers = { ...extra };
    if (this.apiPassword) headers["X-API-Password"] = this.apiPassword;
    if (this.proxyAuth) headers["X-StremThru-Authorization"] = this.proxyAuth;
    return headers;
  }
}
