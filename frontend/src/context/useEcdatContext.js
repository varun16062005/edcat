import { useContext } from "react";
import { EcdatContext } from "./EcdatContextValue";

export function useEcdatContext() {
  const context = useContext(EcdatContext);

  if (!context) {
    throw new Error("useEcdatContext must be used inside EcdatProvider");
  }

  return context;
}

