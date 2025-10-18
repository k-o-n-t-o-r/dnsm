export function validateMailbox(s) {
  const v = (s || "").trim().toLowerCase();
  return /^[0-9a-f]{12}$/.test(v) ? v : null;
}

export function randomMailbox() {
  try {
    const a = crypto.getRandomValues(new Uint32Array(2));
    const v = (BigInt(a[0] & 0xffff) << 32n) | BigInt(a[1]);
    return v.toString(16).padStart(12, "0");
  } catch {
    const hi = Math.floor(Math.random() * 0x10000);
    const lo = Math.floor(Math.random() * 0xffffffff);
    const v = (BigInt(hi) << 32n) | BigInt(lo);
    return v.toString(16).padStart(12, "0");
  }
}
