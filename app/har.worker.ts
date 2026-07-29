/// <reference lib="webworker" />

import { analyzeHar, parseHar, type Analysis } from "./trace-engine";
import { compareAnalyses, type HarComparison } from "./trace-compare";

type AnalyzeMessage =
  | {
      type: "analyze";
      buffer: ArrayBuffer;
      sourceName: string;
    }
  | {
      type: "compare";
      baselineBuffer: ArrayBuffer;
      baselineName: string;
      changedBuffer: ArrayBuffer;
      changedName: string;
    };

type WorkerResponse =
  | { type: "progress"; message: string }
  | { type: "complete"; analysis: Analysis }
  | { type: "comparison-complete"; comparison: HarComparison }
  | { type: "error"; message: string };

const workerScope = self as DedicatedWorkerGlobalScope;

workerScope.onmessage = (event: MessageEvent<AnalyzeMessage>) => {
  try {
    if (event.data.type === "compare") {
      workerScope.postMessage({
        type: "progress",
        message: "Reading capture A locally…",
      } satisfies WorkerResponse);
      const baselineText = new TextDecoder().decode(event.data.baselineBuffer);
      const baseline = analyzeHar(
        parseHar(baselineText),
        event.data.baselineName,
      );

      workerScope.postMessage({
        type: "progress",
        message: "Reading capture B locally…",
      } satisfies WorkerResponse);
      const changedText = new TextDecoder().decode(event.data.changedBuffer);
      const changed = analyzeHar(parseHar(changedText), event.data.changedName);

      workerScope.postMessage({
        type: "progress",
        message: "Ranking the first structural differences…",
      } satisfies WorkerResponse);
      workerScope.postMessage({
        type: "comparison-complete",
        comparison: compareAnalyses(baseline, changed),
      } satisfies WorkerResponse);
      return;
    }

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
