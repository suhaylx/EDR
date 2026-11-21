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
  // All six fetches begin together and none of their results may be published
  // independently. A stale loader may ignore abort and never resolve.
  const pending=Promise.all(loaders.map(load=>load()));
  if(!signal)return pending as Promise<[A,B,C,D,E,F]>;
  // Reject promptly on cancellation even if a custom fetcher never settles.
  // Promise.race also observes late loader rejections without publishing them.
  let removeAbortListener=()=>{};
  const cancelled=new Promise<never>((_,reject)=>{
    const onAbort=()=>reject(new Error('Lab refresh aborted before commit.'));
    signal.addEventListener('abort',onAbort,{once:true});
    removeAbortListener=()=>signal.removeEventListener('abort',onAbort);
    // A loader can synchronously abort while constructing its Promise.
    if(signal.aborted)onAbort();
  });
  try {
    const values=await Promise.race([pending,cancelled]);
    if(signal.aborted)throw new Error('Lab refresh aborted before commit.');
    return values as [A,B,C,D,E,F];
  } finally {
    removeAbortListener();
  }
}
