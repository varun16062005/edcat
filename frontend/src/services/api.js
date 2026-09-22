const API_BASE_URL = (
  import.meta.env.VITE_API_URL || "/api"
).replace(/\/+$/, "");


/* ============================================================
   SCAN FILE
   ============================================================ */

export async function scanFile(scanInput) {
  if (!scanInput) {
    throw new Error(
      "No file selected."
    );
  }

  const formData =
    new FormData();

  const input = typeof File !== "undefined" && scanInput instanceof File
    ? {
        sourceType: "file",
        projectName: scanInput.name,
        files: [{ file: scanInput, relativePath: scanInput.name }],
      }
    : scanInput;

  const manifest = (input.files || []).map((entry) => ({
    path: entry.relativePath || entry.file?.name || "unknown",
    name: entry.file?.name || "unknown",
    size: entry.file?.size || 0,
    type: entry.file?.type || "",
    client_skip_reason: entry.skipReason || "",
  }));

  const uploadEntries = (input.files || []).filter(
    (entry) => !entry.skipReason
  );

  uploadEntries.forEach((entry) => {
    formData.append(
      uploadEntries.length === 1 ? "file" : "files",
      entry.file,
      entry.file.name
    );
  });

  const relativePaths = (input.files || [])
    .filter((entry) => !entry.skipReason)
    .map((entry) => entry.relativePath || entry.file?.name || "unknown");

  relativePaths.forEach((path) => {
    formData.append("relative_paths", path);
  });

  formData.append("source_type", input.sourceType || "file");
  formData.append("project_name", input.projectName || "Selected project");
  formData.append("manifest", JSON.stringify(manifest));

  let response;

  try {
    response = await fetch(
      `${API_BASE_URL}/scan`,
      {
        method: "POST",
        body: formData,
      }
    );
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error(
        "Cannot connect to the ECDAT backend. The request may have been blocked by CORS, or the API URL may be unreachable.",
        { cause: error }
      );
    }

    throw error;
  }


  /* ----------------------------------------------------------
     BACKEND ERROR
     ---------------------------------------------------------- */

  if (!response.ok) {
    let message =
      "ECDAT scan failed.";

    try {
      const errorData =
        await response.json();

      if (
        errorData?.detail
      ) {
        message = String(
          errorData.detail
        );
      }
    } catch {
      // Keep default error message.
    }

    throw new Error(
      message
    );
  }


  /* ----------------------------------------------------------
     SCAN RESPONSE
     ---------------------------------------------------------- */

  try {
    return await response.json();
  } catch {
    throw new Error(
      "ECDAT returned an invalid scan response."
    );
  }
}


/* ============================================================
   PDF REPORT
   ============================================================

   The local backend does not expose a PDF endpoint. The
   browser print dialog can still save the report as a PDF.
   ============================================================ */

export async function generatePdfReport() {
  if (
    typeof window ===
      "undefined" ||
    typeof window.print !==
      "function"
  ) {
    throw new Error(
      "PDF export is only available in a browser."
    );
  }


  const previousTitle =
    document.title;

  document.title =
    "ecdat-scan-report";


  try {
    window.print();
  } finally {
    document.title =
      previousTitle;
  }
}
