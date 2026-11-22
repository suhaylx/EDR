/** Aligns React lab evidence windows with backend/internal/edr/overview.go:
 * startDay := now.UTC().Truncate(24h).AddDate(0, 0, -(days - 1)).
 * The server reports UTC calendar days, not rolling N*24h hours.
 */
export type UTCWindowDays = 1|7|30;
export function backendUTCWindow(generatedAt:string,days:UTCWindowDays):Readonly<{start:number;end:number;startDay:string}> {
  if(![1,7,30].includes(days))throw new Error('Unsupported backend UTC calendar-day window.');
  const end=Date.parse(generatedAt);
  if(!Number.isFinite(end)||!/^\d{4}-\d\d-\d\dT/.test(generatedAt))
    throw new Error('Invalid Go overview generation timestamp.');
  const midnight=Math.floor(end/86400000)*86400000;
  const start=midnight-(days-1)*86400000;
  return {start,end,startDay:new Date(start).toISOString().slice(0,10)};
}
export function withinBackendUTCWindow(time:number|null,window:Readonly<{start:number;end:number}>):boolean {
  return time!==null&&Number.isFinite(time)&&time>=window.start&&time<=window.end;
}
