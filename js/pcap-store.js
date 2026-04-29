// ブラウザ内 pcap (libpcap classic) ストア。
// localStorage に Base64 で蓄積し、ダウンロード/クリアを提供する。
// LINKTYPE = Ethernet (1)、microsecond resolution。
//
// 公開:
//   RouterPcap.append(routerId, packetBytes, when?)  // 全体 + ルータ別に追記
//   RouterPcap.list() -> ['all', 'R1', ...]
//   RouterPcap.size(name) -> bytes
//   RouterPcap.count(name) -> packet 数
//   RouterPcap.download(name)  // .pcap ファイルを保存
//   RouterPcap.clear(name?)    // name 省略で全削除
(function (global) {
  const PREFIX = 'pcap:';

  // localStorage は文字列のみ。Uint8Array <-> Base64 変換。
  function bytesToB64(u8) {
    let s = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < u8.length; i += CHUNK) {
      s += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
    }
    return btoa(s);
  }
  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function read(name) {
    const v = localStorage.getItem(PREFIX + name);
    return v ? b64ToBytes(v) : null;
  }
  function write(name, bytes) {
    localStorage.setItem(PREFIX + name, bytesToB64(bytes));
  }

  function globalHeader() {
    const buf = new Uint8Array(24);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 0xa1b2c3d4, true); // magic LE
    dv.setUint16(4, 2, true);
    dv.setUint16(6, 4, true);
    dv.setInt32(8, 0, true);
    dv.setUint32(12, 0, true);
    dv.setUint32(16, 65535, true);
    dv.setUint32(20, 1, true);          // LINKTYPE_ETHERNET
    return buf;
  }
  function recordHeader(len, when) {
    const buf = new Uint8Array(16);
    const dv = new DataView(buf.buffer);
    const sec = Math.floor(when / 1000);
    const usec = (when % 1000) * 1000;
    dv.setUint32(0, sec, true);
    dv.setUint32(4, usec, true);
    dv.setUint32(8, len, true);
    dv.setUint32(12, len, true);
    return buf;
  }

  function appendOne(name, packet, when) {
    const cur = read(name);
    const head = cur || globalHeader();
    const rec = recordHeader(packet.length, when);
    const out = new Uint8Array(head.length + rec.length + packet.length);
    out.set(head, 0);
    out.set(rec, head.length);
    out.set(packet, head.length + rec.length);
    write(name, out);
    // パケット数は別キーで管理（毎回パースしないため）
    const ck = PREFIX + 'count:' + name;
    localStorage.setItem(ck, String((parseInt(localStorage.getItem(ck), 10) || 0) + 1));
  }

  function append(routerId, packet, when) {
    const ts = when || Date.now();
    appendOne('all', packet, ts);
    if (routerId) appendOne(String(routerId), packet, ts);
  }

  function list() {
    const out = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith(PREFIX) && !k.startsWith(PREFIX + 'count:')) {
        out.push(k.slice(PREFIX.length));
      }
    }
    return out.sort();
  }
  function size(name) {
    const v = localStorage.getItem(PREFIX + name);
    return v ? Math.floor(v.length * 3 / 4) : 0; // base64 概算
  }
  function count(name) {
    return parseInt(localStorage.getItem(PREFIX + 'count:' + name), 10) || 0;
  }

  function download(name) {
    const bytes = read(name);
    if (!bytes) { alert(`pcap "${name}" が空です`); return; }
    const blob = new Blob([bytes], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name}.pcap`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
  }

  function clear(name) {
    if (name) {
      localStorage.removeItem(PREFIX + name);
      localStorage.removeItem(PREFIX + 'count:' + name);
      return;
    }
    list().forEach(n => clear(n));
  }

  global.RouterPcap = { append, list, size, count, download, clear };
})(window);
