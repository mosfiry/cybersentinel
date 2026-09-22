let counter = 0;
/** Unique, non-guessable-enough client request id (no secrets involved). */
export function newRequestId() {
  counter = (counter + 1) % 100000;
  return "ui-" + Date.now().toString(36) + "-" + counter.toString(36) + "-" + Math.random().toString(36).slice(2, 8);
}
