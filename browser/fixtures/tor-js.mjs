// Synthetic boundary fixture, selected only by the CI page's import map.
// It opens no sockets and supplies no evidence about actual Tor connectivity.
let scenario;
export function configure(value = {}) {
  scenario = { calls: [], constructed: 0, closed: 0, readyCalls: 0, ...value };
  return scenario;
}
export class Log { constructor() {} }
export class TorClient {
  static onionClientSupported() { return scenario.support?.() ?? true; }
  static onionStreamSupported() { return true; }
  static onionServiceSupported() { return true; }
  constructor(options) {
    this.fixture = scenario;
    this.fixture.constructed++;
    this.fixture.options = options;
    this.fixture.construct?.();
  }
  ready() { this.fixture.readyCalls++; return this.fixture.ready?.(); }
  connectOnion(...args) {
    this.fixture.calls.push(['connect', ...args]);
    return this.fixture.connect?.(...args);
  }
  hostOnion(...args) {
    this.fixture.calls.push(['listen', ...args]);
    return this.fixture.listen?.(...args);
  }
  close() { this.fixture.closed++; this.fixture.close?.(); }
}
