// Scripted framed I/O, actual generated Wasm Inbox/signatures/persistence.
// These cases are transport ownership evidence, not additional Tor evidence.
import { LiveInboxStream } from './live-stream.mjs';
function assert(value,label) {if(!value)throw new Error(`live contract: ${label}`);}
function pair() {
 const sides=[{queue:[],wait:[],closed:false},{queue:[],wait:[],closed:false}];
 const endpoints=sides.map((self,index)=>({
  pauseNext:false,failNext:false,release:undefined,captured:undefined,
  async send(bytes) {
   if(this.failNext){this.failNext=false;throw new Error('scripted write failure');}
   this.captured=bytes.slice();
   if(this.pauseNext){this.pauseNext=false;await new Promise(resolve=>{this.release=resolve;});}
   if(self.closed)throw new Error('scripted closed write');
   const other=sides[1-index];if(other.closed)throw new Error('scripted peer loss');
   const value=bytes.slice();const waiter=other.wait.shift();if(waiter)waiter.resolve(value);else other.queue.push(value);
  },
  receive() {if(self.queue.length)return Promise.resolve(self.queue.shift());if(self.closed)return Promise.reject(new Error('scripted EOF'));return new Promise((resolve,reject)=>self.wait.push({resolve,reject}));},
  close() {self.closed=true;for(const waiter of self.wait.splice(0))waiter.reject(new Error('scripted EOF'));},
 }));return endpoints;
}
export async function runLiveStreamContract(a,b,key,context,saveA,saveB) {
 const [sa,sb]=pair();const until=Math.floor(Date.now()/1000)+120;
 const [la,lb]=await Promise.all([
  LiveInboxStream.open(sa,a,{peerDevice:b.chatPublicKey(),until,key,context,persist:saveA}),
  LiveInboxStream.open(sb,b,{peerDevice:a.chatPublicKey(),until,key,context,persist:saveB}),
 ]);
 try {
  await la.send(new Uint8Array([7,0,255]));
  const received=await lb.receive();assert(received.bytes[2]===255,'actual authenticated payload');received.free();
  await lb.send(new Uint8Array([8]));const reply=await la.receive();assert(reply.bytes[0]===8,'ACK recovery and next live data');reply.free();
  assert(JSON.parse(a.liveDeliveries()).some(d=>d.outgoing&&d.status==='accepted'),'write alone did not mark acceptance');
  sa.pauseNext=true;const pending=la.send(new Uint8Array([9]));
  const outcome=pending.then(()=>false,()=>true);
  for(let i=0;i<100 && !sa.release;i++)await new Promise(resolve=>setTimeout(resolve,1));
  assert(typeof sa.release==='function','write entered transport');const late=sa.captured.slice();
  await la.close();sa.release();assert(await outcome,'late write rejects after close');
  assert(!a.canTransmitLiveWire(late) && JSON.parse(a.liveDeliveries()).some(d=>d.outgoing&&d.status==='canceledUnconfirmed'),'late application stays canceled');
  assert(!a.isClosed(b.memberId()),'I/O close never blocks member');
 } finally {await Promise.allSettled([la.close(),lb.close()]);}
 // An accepted plaintext result remains owned by the adapter until ACK flushing
 // succeeds. A failed write must free it while preserving durable peer history.
 const [sc,sd]=pair();
 const [lc,ld]=await Promise.all([
  LiveInboxStream.open(sc,a,{peerDevice:b.chatPublicKey(),until,key,context,persist:saveA}),
  LiveInboxStream.open(sd,b,{peerDevice:a.chatPublicKey(),until,key,context,persist:saveB}),
 ]);
 const originalReceive=b.receive;
 let receivedPayloads=0,freedPayloads=0;
 b.receive=async function(...args) {
  const result=await originalReceive.apply(this,args);
  if(result.kind==='bytes') {
   receivedPayloads+=1;
   const originalFree=result.free;
   result.free=function(){freedPayloads+=1;return originalFree.call(this);};
  }
  return result;
 };
 try {
  const historySize=()=>{const entries=b.acceptedLiveHistory();for(const entry of entries)entry.free();return entries.length;};
  const historyBefore=historySize();
  await lc.send(new Uint8Array([21,0,255]));
  sd.failNext=true;
  let rejected=false;
  try {const result=await ld.receive();result.free();} catch {rejected=true;}
  assert(rejected&&ld.closed,'ACK write failure closes receive');
  assert(receivedPayloads===1&&freedPayloads===1,'failed ACK frees accepted Wasm payload exactly once');
  assert(historySize()===historyBefore+1,'failed ACK retains accepted history');
 } finally {
  b.receive=originalReceive;
  await Promise.allSettled([lc.close(),ld.close()]);
 }
}
