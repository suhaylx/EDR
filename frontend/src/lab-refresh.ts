/**
 * The lab SOC dashboard must publish no partial snapshot. The six requests
 * are independently fetched read-only JSON and are NOT a backend transaction.
 * The caller must still clear previously loaded state before dispatch.
 */
export type SixEvidenceLoaders<A,B,C,D,E,F> = readonly [
  () => Promise<A>,
  () => Promise<B>,
  () => Promise<C>,
  () => Promise<D>,
  () => Promise<E>,
  () => Promise<F>,
];
export async function loadSixReadOnlyEvidence<A,B,C,D,E,F>(
  loaders: SixEvidenceLoaders<A,B,C,D,E,F>, signal?:AbortSignal,
):Promise<[A,B,C,D,E,F]> {
  if(signal?.aborted)throw new Error('Lab refresh aborted before dispatch.');
  // Promise.all rejects without returning a partial or last-known-good array.
  const values=await Promise.all(loaders.map(load=>load()));
  // A fetch mock or custom adapter may ignore AbortSignal: check again before
  // publishing all six results into React state.
  if(signal?.aborted)throw new Error('Lab refresh aborted before commit.');
  return values as [A,B,C,D,E,F];
}
