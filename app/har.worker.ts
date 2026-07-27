/// <reference lib="webworker" />

import { analyzeHar, parseHar, type Analysis } from "./trace-engine";

type AnalyzeMessage = {
  type: "analyze";
  buffer: ArrayBuffer;
  sourceName: string;
};

type WorkerResponse =
  | { type: "progress"; message: string }
  | { type: "complete"; analysis: Analysis }
  | { type: "error"; message: string };

const workerScope = self as DedicatedWorkerGlobalScope;

workerScope.onmessage = (event: MessageEvent<AnalyzeMessage>) => {
  if (event.data.type !== "analyze") return;

  try {
    workerScope.postMessage({
      type: "progress",
      message: "Parsing and validating the HAR…",
    } satisfies WorkerResponse);
    const text = new TextDecoder().decode(event.data.buffer);
    const har = parseHar(text);

    workerScope.postMessage({
      type: "progress",
      message: "Sanitizing evidence and ranking failures…",
    } satisfies WorkerResponse);
    const analysis = analyzeHar(har, event.data.sourceName);

    workerScope.postMessage({
      type: "complete",
      analysis,
    } satisfies WorkerResponse);
  } catch (reason) {
    workerScope.postMessage({
      type: "error",
      message: reason instanceof Error ? reason.message : "The HAR could not be analyzed.",
    } satisfies WorkerResponse);
  }
};

export {};
