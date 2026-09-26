import { artifactEntityId } from "../context/entityIds";
import { getArtifactHash } from "../utils/cryptoHash";

export const PREVIOUS_SCAN_SNAPSHOT_KEY = "ecdatPreviousScanSnapshot";

export function identityFor(artifact, index) {
  return artifactEntityId(artifact, index);
}

export function classifyRecords(artifacts = [], previousSnapshot) {
  const previousHashes = previousSnapshot?.hashes || {};
  const previousIdentities = new Set(Object.keys(previousHashes));
  const currentIdentities = new Set();
  const records = artifacts.map((artifact, index) => {
    const identity = identityFor(artifact, index);
    currentIdentities.add(identity);
    const currentHash = getArtifactHash(artifact, index);
    const previousHash = previousHashes[identity];
    let status = "NEW";
    if (previousHash) {
      status = previousHash === currentHash ? "UNCHANGED" : "CHANGED";
    } else if (!previousIdentities.size) {
      status = "UNCHANGED";
    }
    return {
      artifact,
      identity,
      currentHash,
      previousHash: previousHash || "",
      status,
    };
  });
  const removed = [...previousIdentities]
    .filter((identity) => !currentIdentities.has(identity))
    .map((identity) => ({
      identity,
      currentHash: "",
      previousHash: previousHashes[identity],
      status: "REMOVED",
      artifact: { file: identity, algorithm: "Removed artifact" },
    }));

  return {
    records: [...records, ...removed],
    summary: {
      scanned: artifacts.length,
      unchanged: records.filter((record) => record.status === "UNCHANGED").length,
      changed: records.filter((record) => record.status === "CHANGED").length,
      new: records.filter((record) => record.status === "NEW").length,
      removed: removed.length,
    },
  };
}

export function snapshotCurrentScan(result) {
  if (!result?.artifacts) return;
  const hashes = Object.fromEntries(
    result.artifacts.map((artifact, index) => [
      identityFor(artifact, index),
      getArtifactHash(artifact, index),
    ])
  );
  localStorage.setItem(PREVIOUS_SCAN_SNAPSHOT_KEY, JSON.stringify({
    name: result.input?.name,
    timestamp: result.cbom?.metadata?.timestamp || new Date().toISOString(),
    hashes,
  }));
}

export function readPreviousSnapshot() {
  try {
    return JSON.parse(localStorage.getItem(PREVIOUS_SCAN_SNAPSHOT_KEY) || "null");
  } catch {
    return null;
  }
}
