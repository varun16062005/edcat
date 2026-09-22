export function makeEntityId(type, value) {
  const normalized = String(value || "unknown")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");

  return `${type}:${normalized || "unknown"}`;
}

export function artifactEntityId(artifact, index = 0) {
  return makeEntityId(
    "artifact",
    `${artifact?.file || "unknown"}:${artifact?.line || "unknown"}:${artifact?.algorithm || index}`
  );
}

export function fileEntityId(file, index = 0) {
  return makeEntityId(
    "file",
    file?.path || file?.name || index
  );
}

