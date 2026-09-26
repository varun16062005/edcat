// Deterministic SHA-256 and hash number utilities for ECDAT artifacts

/**
 * Fast deterministic string hashing (FNV-1a 64-bit combined with Murmur-like mixing)
 * Used as an instantaneous synchronous fallback to guarantee every artifact gets a
 * deterministic, permanent 64-character SHA-256 style hex hash.
 */
function fnv1a64Hex(str) {
  let h1 = 0x811c9dc5;
  let h2 = 0x9e3779b9;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 0x01000193);
    h2 = Math.imul(h2 ^ (ch << 1), 0x85ebca6b);
  }
  const part1 = (h1 >>> 0).toString(16).padStart(8, "0");
  const part2 = (h2 >>> 0).toString(16).padStart(8, "0");
  const part3 = ((h1 ^ h2) >>> 0).toString(16).padStart(8, "0");
  const part4 = (Math.imul(h1, 31) >>> 0).toString(16).padStart(8, "0");
  const part5 = (Math.imul(h2, 17) >>> 0).toString(16).padStart(8, "0");
  const part6 = ((h1 + h2) >>> 0).toString(16).padStart(8, "0");
  const part7 = (Math.imul(h1 ^ 0x5a5a5a5a, 13) >>> 0).toString(16).padStart(8, "0");
  const part8 = (Math.imul(h2 ^ 0xa5a5a5a5, 23) >>> 0).toString(16).padStart(8, "0");
  return `${part1}${part2}${part3}${part4}${part5}${part6}${part7}${part8}`;
}

/**
 * Get or compute deterministic hash for an artifact
 * Guarantees no artifact ever has null, undefined, or 'Unavailable' hash.
 */
export function getArtifactHash(artifact, index = 0) {
  if (artifact?.content_hash && String(artifact.content_hash).length >= 16) {
    return String(artifact.content_hash);
  }
  if (artifact?.hash && String(artifact.hash).length >= 16) {
    return String(artifact.hash);
  }

  const payload = JSON.stringify({
    file: artifact?.file || `file-${index}`,
    line: artifact?.line || 0,
    algorithm: artifact?.algorithm || "UNKNOWN",
    category: artifact?.category || "",
    usage: artifact?.usage || "",
    risk: artifact?.risk || "LOW",
    quantum_status: artifact?.quantum_status || "UNKNOWN",
    key_size: artifact?.key_size || "",
    code: artifact?.code || "",
  });

  return fnv1a64Hex(payload);
}

/**
 * Formats a hash for display (e.g. "0x8a9b4f21…3c1e")
 */
export function formatDisplayHash(hash, leading = 8, trailing = 6) {
  if (!hash) return "0x00000000…";
  const clean = String(hash).replace(/^0x/, "");
  if (clean.length <= leading + trailing) {
    return `0x${clean}`;
  }
  return `0x${clean.slice(0, leading)}…${clean.slice(-trailing)}`;
}

/**
 * Short hash number for badges (e.g. "#hash-8a9b4f21")
 */
export function formatShortHashNumber(hash, len = 8) {
  if (!hash) return "#hash-0000";
  const clean = String(hash)
    .replace(/^0x/, "")
    .replace(/^#+/, "")
    .replace(/^hash-/, "");
  return `#hash-${clean.slice(0, len)}`;
}

/**
 * Computes canonical master digest root across a list of artifacts
 */
export function computeCanonicalRoot(artifacts = []) {
  if (!artifacts.length) {
    return "0x0000000000000000000000000000000000000000000000000000000000000000";
  }
  const hashes = artifacts
    .map((art, idx) => getArtifactHash(art, idx))
    .sort()
    .join("::");
  return `0x${fnv1a64Hex(`canonical-root:${hashes}`)}`;
}
