// パケット・キャプチャ：ルータごとに購読者を持ち、tshark 風の 1 行サマリを配信する。
// データ源は js/sender.js から。サーバ通信は一切しない。
//
// 公開:
//   RouterCapture.subscribe(routerId, cb)   // cb(line, raw, meta)
//   RouterCapture.unsubscribe(routerId, cb)
//   RouterCapture.emit(routerId, packet)    // sender が呼ぶ
//   RouterCapture.decode(packet) -> string
(function (global) {
  const subs = new Map();   // id -> Set<cb>

  // ---------- 数値/IP/MAC ----------
  function ip4(b, off) { return `${b[off]}.${b[off+1]}.${b[off+2]}.${b[off+3]}`; }
  function mac(b, off) {
    return [0,1,2,3,4,5].map(i => b[off+i].toString(16).padStart(2,'0')).join(':');
  }
  function u16(b, off) { return (b[off] << 8) | b[off+1]; }
  function pad(s, n) { return String(s).length >= n ? String(s) : String(s) + ' '.repeat(n - String(s).length); }
  function hhmmss(d) {
    return d.toTimeString().slice(0,8) + '.' +
      String(d.getMilliseconds()).padStart(3,'0');
  }

  // ---------- EtherType レジストリ（追加・変更はここだけ） ----------
  const ETYPE = {
    0x0800: 'IPv4',
    0x0806: 'ARP',
    0x0842: 'Wake-on-LAN',
    0x86DD: 'IPv6',
    0x8100: 'VLAN (802.1Q)',
    0x8847: 'MPLS unicast',
    0x8848: 'MPLS multicast',
    0x8863: 'PPPoE Discovery',
    0x8864: 'PPPoE Session',
    0x888E: '802.1X',
    0x9100: 'VLAN double-tagged',
    0x9200: 'VLAN double-tagged',
  };
  // EtherType 値 → 表示文字列 (例: "0x0800 (IPv4)")
  function etypeStr(val) {
    const hex = '0x' + val.toString(16).padStart(4, '0').toUpperCase();
    const name = ETYPE[val];
    return name ? `${hex} (${name})` : hex;
  }

  // ---------- TCP flags ----------
  function tcpFlags(byte) {
    const map = [['F',1],['S',2],['R',4],['P',8],['A',16],['U',32]];
    return map.filter(([_,m]) => byte & m).map(([n]) => n).join('') || '.';
  }

  // MAC byte0 から IG / LG ビットを解析して文字列を返す
  // IG bit (bit0): 0=Individual(unicast) / 1=Group(multicast/broadcast)
  // LG bit (bit1): 0=Globally administered(OUI) / 1=Locally administered
  function macBits(b0) {
    const ig = b0 & 0x01;
    const lg = (b0 >> 1) & 0x01;
    return `IG=${ig}(${ig ? 'Group' : 'Individual'}) LG=${lg}(${lg ? 'Local' : 'Global'})`;
  }

  function decode(pkt) {
    if (!pkt || pkt.length < 14) return `(short ${pkt && pkt.length}B)`;
    const ethertype = u16(pkt, 12);
    const total = pkt.length;

    // ARP
    if (ethertype === 0x0806) {
      const op   = u16(pkt, 14 + 6);
      const sIp  = ip4(pkt, 14 + 14);
      const tIp  = ip4(pkt, 14 + 24);
      const sMac = mac(pkt, 14 + 8);
      const bits = macBits(pkt[14 + 8]);
      const isGarp = sIp === tIp;
      if (op === 1) {
        const prefix = isGarp ? `Gratuitous ARP for ${sIp} (Request)` : `ARP  Who has ${tIp}?  Tell ${sIp}`;
        return `${prefix}  (${total}B)`;
      }
      if (op === 2) {
        const prefix = isGarp ? `Gratuitous ARP for ${sIp} (Reply)` : `ARP  ${sIp} is at ${sMac} [${bits}]`;
        return `${prefix}  (${total}B)`;
      }
      return `ARP  op=${op}  (${total}B)`;
    }

    // IPv4
    if (ethertype === 0x0800) {
      const ihl = (pkt[14] & 0x0f) * 4;
      const proto = pkt[14 + 9];
      const src = ip4(pkt, 14 + 12);
      const dst = ip4(pkt, 14 + 16);
      const ttl = pkt[14 + 8];
      const ipPayloadOff = 14 + ihl;

      if (proto === 1) { // ICMP
        const t = pkt[ipPayloadOff];
        const c = pkt[ipPayloadOff + 1];
        const id = u16(pkt, ipPayloadOff + 4);
        const seq = u16(pkt, ipPayloadOff + 6);
        const name = (t === 8 ? 'echo request' : t === 0 ? 'echo reply' : `type=${t}`);
        return `IP   ${pad(src,15)} > ${pad(dst,15)}  ICMP ${name} id=${id} seq=${seq} ttl=${ttl} (${total}B)`;
      }
      if (proto === 17) { // UDP
        const sp = u16(pkt, ipPayloadOff);
        const dp = u16(pkt, ipPayloadOff + 2);
        const len = u16(pkt, ipPayloadOff + 4);
        return `IP   ${pad(src,15)} > ${pad(dst,15)}  UDP ${sp} > ${dp} len=${len} ttl=${ttl} (${total}B)`;
      }
      if (proto === 6) { // TCP (BGP の可能性も)
        const sp = u16(pkt, ipPayloadOff);
        const dp = u16(pkt, ipPayloadOff + 2);
        const seq = ((pkt[ipPayloadOff+4]<<24)|(pkt[ipPayloadOff+5]<<16)|(pkt[ipPayloadOff+6]<<8)|pkt[ipPayloadOff+7])>>>0;
        const dataOff = (pkt[ipPayloadOff + 12] >> 4) * 4;
        const flags = tcpFlags(pkt[ipPayloadOff + 13]);
        const tcpPayload = ipPayloadOff + dataOff;
        // BGP: dport/sport が 179 で marker(16x0xff) ヘッダがある
        if ((sp === 179 || dp === 179) && tcpPayload + 19 <= pkt.length) {
          let isBgp = true;
          for (let i = 0; i < 16; i++) if (pkt[tcpPayload + i] !== 0xff) { isBgp = false; break; }
          if (isBgp) {
            const bgpType = pkt[tcpPayload + 18];
            const bgpName = ['','OPEN','UPDATE','NOTIFICATION','KEEPALIVE'][bgpType] || `type=${bgpType}`;
            return `IP   ${pad(src,15)} > ${pad(dst,15)}  BGP ${bgpName} (${total}B)`;
          }
        }
        return `IP   ${pad(src,15)} > ${pad(dst,15)}  TCP ${sp} > ${dp} [${flags}] seq=${seq} ttl=${ttl} (${total}B)`;
      }
      if (proto === 89) { // OSPF
        const t = pkt[ipPayloadOff + 1];
        const rid = ip4(pkt, ipPayloadOff + 4);
        const area = ip4(pkt, ipPayloadOff + 8);
        const name = ['','Hello','DBD','LS-Req','LS-Upd','LS-Ack'][t] || `type=${t}`;
        return `IP   ${pad(src,15)} > ${pad(dst,15)}  OSPF ${name} rid=${rid} area=${area} (${total}B)`;
      }
      return `IP   ${pad(src,15)} > ${pad(dst,15)}  proto=${proto} (${total}B)`;
    }

    return `Ethernet type=${etypeStr(ethertype)} (${total}B)`;
  }

  function format(routerId, pkt, when) {
    return `${hhmmss(new Date(when))}  ${pad(routerId, 6)}  ${decode(pkt)}`;
  }

  // ----------------------------------------------------------------
  // 詳細ツリー: Wireshark 風の階層 + 各フィールドのバイト範囲を持つ。
  // 戻り値は配列。各要素は {label, range:[off,len], children?:[]}
  // ----------------------------------------------------------------
  function fld(label, off, len, children) {
    const o = { label, range: [off, len] };
    if (children) o.children = children;
    return o;
  }

  function ethTree(pkt) {
    const dst = mac(pkt, 0), src = mac(pkt, 6), et = u16(pkt, 12);
    return fld(`Ethernet II, Src: ${src}, Dst: ${dst}`, 0, 14, [
      fld(`Destination: ${dst}`, 0, 6, [
        fld(macBits(pkt[0]), 0, 1),
      ]),
      fld(`Source: ${src}`, 6, 6, [
        fld(macBits(pkt[6]), 6, 1),
      ]),
      fld(`Type: ${etypeStr(et)}`, 12, 2),
    ]);
  }

  function ipv4Tree(pkt, off) {
    const ihl = (pkt[off] & 0x0f) * 4;
    const total = u16(pkt, off + 2);
    const id = u16(pkt, off + 4);
    const fl = u16(pkt, off + 6);
    const ttl = pkt[off + 8];
    const proto = pkt[off + 9];
    const csum = u16(pkt, off + 10);
    const src = ip4(pkt, off + 12), dst = ip4(pkt, off + 16);
    return fld(`Internet Protocol Version 4, Src: ${src}, Dst: ${dst}`, off, ihl, [
      fld(`Version: 4`, off, 1),
      fld(`Header Length: ${ihl} bytes`, off, 1),
      fld(`Total Length: ${total}`, off + 2, 2),
      fld(`Identification: 0x${id.toString(16).padStart(4,'0')}`, off + 4, 2),
      fld(`Flags / Fragment offset: 0x${fl.toString(16).padStart(4,'0')}`, off + 6, 2),
      fld(`Time to Live: ${ttl}`, off + 8, 1),
      fld(`Protocol: ${proto}`, off + 9, 1),
      fld(`Header checksum: 0x${csum.toString(16).padStart(4,'0')}`, off + 10, 2),
      fld(`Source: ${src}`, off + 12, 4),
      fld(`Destination: ${dst}`, off + 16, 4),
    ]);
  }

  function arpTree(pkt, off) {
    const op = u16(pkt, off + 6);
    const sMac = mac(pkt, off + 8), sIp = ip4(pkt, off + 14);
    const tMac = mac(pkt, off + 18), tIp = ip4(pkt, off + 24);
    return fld(`Address Resolution Protocol (${op === 1 ? 'request' : op === 2 ? 'reply' : 'op='+op})`, off, 28, [
      fld(`Hardware type: Ethernet (1)`, off, 2),
      fld(`Protocol type: ${etypeStr(0x0800)}`, off + 2, 2),
      fld(`Hardware size: 6`, off + 4, 1),
      fld(`Protocol size: 4`, off + 5, 1),
      fld(`Opcode: ${op} (${op === 1 ? 'request' : op === 2 ? 'reply' : 'unknown'})`, off + 6, 2),
      fld(`Sender MAC: ${sMac}`, off + 8, 6),
      fld(`Sender IP:  ${sIp}`, off + 14, 4),
      fld(`Target MAC: ${tMac}`, off + 18, 6),
      fld(`Target IP:  ${tIp}`, off + 24, 4),
    ]);
  }

  function icmpTree(pkt, off, end) {
    const t = pkt[off], c = pkt[off + 1];
    const cs = u16(pkt, off + 2);
    const id = u16(pkt, off + 4), seq = u16(pkt, off + 6);
    const name = (t === 8 ? 'Echo (ping) request' : t === 0 ? 'Echo (ping) reply' : `type=${t}`);
    return fld(`Internet Control Message Protocol`, off, end - off, [
      fld(`Type: ${t} (${name})`, off, 1),
      fld(`Code: ${c}`, off + 1, 1),
      fld(`Checksum: 0x${cs.toString(16).padStart(4,'0')}`, off + 2, 2),
      fld(`Identifier: ${id}`, off + 4, 2),
      fld(`Sequence: ${seq}`, off + 6, 2),
      fld(`Data: ${end - off - 8} bytes`, off + 8, end - off - 8),
    ]);
  }

  function udpTree(pkt, off, end) {
    const sp = u16(pkt, off), dp = u16(pkt, off + 2);
    const ln = u16(pkt, off + 4), cs = u16(pkt, off + 6);
    return fld(`User Datagram Protocol, Src Port: ${sp}, Dst Port: ${dp}`, off, end - off, [
      fld(`Source Port: ${sp}`, off, 2),
      fld(`Destination Port: ${dp}`, off + 2, 2),
      fld(`Length: ${ln}`, off + 4, 2),
      fld(`Checksum: 0x${cs.toString(16).padStart(4,'0')}`, off + 6, 2),
      fld(`Data: ${end - off - 8} bytes`, off + 8, end - off - 8),
    ]);
  }

  function tcpTree(pkt, off, end) {
    const sp = u16(pkt, off), dp = u16(pkt, off + 2);
    const seq = ((pkt[off+4]<<24)|(pkt[off+5]<<16)|(pkt[off+6]<<8)|pkt[off+7])>>>0;
    const ack = ((pkt[off+8]<<24)|(pkt[off+9]<<16)|(pkt[off+10]<<8)|pkt[off+11])>>>0;
    const dataOff = (pkt[off + 12] >> 4) * 4;
    const flags = pkt[off + 13];
    const win = u16(pkt, off + 14);
    const cs = u16(pkt, off + 16);
    return fld(`Transmission Control Protocol, Src Port: ${sp}, Dst Port: ${dp}`, off, end - off, [
      fld(`Source Port: ${sp}`, off, 2),
      fld(`Destination Port: ${dp}`, off + 2, 2),
      fld(`Sequence Number: ${seq}`, off + 4, 4),
      fld(`Acknowledgment Number: ${ack}`, off + 8, 4),
      fld(`Data Offset: ${dataOff} bytes`, off + 12, 1),
      fld(`Flags: 0x${flags.toString(16).padStart(2,'0')} (${tcpFlags(flags)})`, off + 13, 1),
      fld(`Window: ${win}`, off + 14, 2),
      fld(`Checksum: 0x${cs.toString(16).padStart(4,'0')}`, off + 16, 2),
      fld(`Payload: ${end - off - dataOff} bytes`, off + dataOff, end - off - dataOff),
    ]);
  }

  function bgpTree(pkt, off, end) {
    const len = u16(pkt, off + 16);
    const t = pkt[off + 18];
    const name = ['','OPEN','UPDATE','NOTIFICATION','KEEPALIVE'][t] || `type=${t}`;
    const children = [
      fld(`Marker (16 bytes, 0xff..)`, off, 16),
      fld(`Length: ${len}`, off + 16, 2),
      fld(`Type: ${t} (${name})`, off + 18, 1),
    ];
    if (name === 'OPEN' && off + 28 <= end) {
      const ver = pkt[off + 19];
      const myAs = u16(pkt, off + 20);
      const hold = u16(pkt, off + 22);
      const bgpId = ip4(pkt, off + 24);
      children.push(fld(`Version: ${ver}`, off + 19, 1));
      children.push(fld(`My AS: ${myAs}`, off + 20, 2));
      children.push(fld(`Hold Time: ${hold}`, off + 22, 2));
      children.push(fld(`BGP Identifier: ${bgpId}`, off + 24, 4));
    } else if (name === 'NOTIFICATION' && off + 21 <= end) {
      children.push(fld(`Error Code: ${pkt[off + 19]}`, off + 19, 1));
      children.push(fld(`Subcode: ${pkt[off + 20]}`, off + 20, 1));
    }
    return fld(`Border Gateway Protocol - ${name}`, off, len, children);
  }

  function ospfTree(pkt, off, end) {
    const t = pkt[off + 1];
    const len = u16(pkt, off + 2);
    const rid = ip4(pkt, off + 4);
    const area = ip4(pkt, off + 8);
    const cs = u16(pkt, off + 12);
    const name = ['','Hello','DBD','LS-Req','LS-Upd','LS-Ack'][t] || `type=${t}`;
    const children = [
      fld(`Version: 2`, off, 1),
      fld(`Type: ${t} (${name})`, off + 1, 1),
      fld(`Length: ${len}`, off + 2, 2),
      fld(`Router ID: ${rid}`, off + 4, 4),
      fld(`Area: ${area}`, off + 8, 4),
      fld(`Checksum: 0x${cs.toString(16).padStart(4,'0')}`, off + 12, 2),
    ];
    if (name === 'Hello' && off + 24 + 20 <= end) {
      const mask = ip4(pkt, off + 24);
      const hi = u16(pkt, off + 28);
      const opt = pkt[off + 30], pri = pkt[off + 31];
      const di = ((pkt[off+32]<<24)|(pkt[off+33]<<16)|(pkt[off+34]<<8)|pkt[off+35])>>>0;
      children.push(fld(`Network Mask: ${mask}`, off + 24, 4));
      children.push(fld(`Hello Interval: ${hi}`, off + 28, 2));
      children.push(fld(`Options: 0x${opt.toString(16).padStart(2,'0')}`, off + 30, 1));
      children.push(fld(`Router Priority: ${pri}`, off + 31, 1));
      children.push(fld(`Dead Interval: ${di}`, off + 32, 4));
    }
    return fld(`Open Shortest Path First - ${name}`, off, end - off, children);
  }

  // パケット全体 → ツリー(配列) + サマリ
  function decodeTree(pkt) {
    const tree = [];
    const summary = decode(pkt);
    if (!pkt || pkt.length < 14) return { tree, summary };

    tree.push(ethTree(pkt));
    const et = u16(pkt, 12);

    if (et === 0x0806 && pkt.length >= 42) {
      tree.push(arpTree(pkt, 14));
      return { tree, summary };
    }
    if (et === 0x0800) {
      const ipOff = 14;
      const ihl = (pkt[ipOff] & 0x0f) * 4;
      tree.push(ipv4Tree(pkt, ipOff));
      const proto = pkt[ipOff + 9];
      const l4Off = ipOff + ihl;
      const end = pkt.length;
      if (proto === 1) tree.push(icmpTree(pkt, l4Off, end));
      else if (proto === 17) tree.push(udpTree(pkt, l4Off, end));
      else if (proto === 6) {
        tree.push(tcpTree(pkt, l4Off, end));
        const dataOff = (pkt[l4Off + 12] >> 4) * 4;
        const sp = u16(pkt, l4Off), dp = u16(pkt, l4Off + 2);
        const tcpPayload = l4Off + dataOff;
        if ((sp === 179 || dp === 179) && tcpPayload + 19 <= end) {
          let isBgp = true;
          for (let i = 0; i < 16; i++) if (pkt[tcpPayload + i] !== 0xff) { isBgp = false; break; }
          if (isBgp) tree.push(bgpTree(pkt, tcpPayload, end));
        }
      }
      else if (proto === 89) tree.push(ospfTree(pkt, l4Off, end));
    }
    return { tree, summary };
  }

  function subscribe(id, cb) {
    if (!subs.has(id)) subs.set(id, new Set());
    subs.get(id).add(cb);
  }
  function unsubscribe(id, cb) {
    const s = subs.get(id);
    if (!s) return;
    s.delete(cb);
    if (s.size === 0) subs.delete(id);
  }
  // opts: number (後方互換) または { when?, iface? }
  function emit(id, pkt, opts) {
    const t = (typeof opts === 'number' ? opts : (opts && opts.when)) || Date.now();
    const iface = (opts && typeof opts === 'object' && opts.iface) || null;
    const line = format(id, pkt, t);
    const meta = { ts: t, routerId: id, iface };
    const set = subs.get(id);
    if (set) set.forEach(cb => { try { cb(line, pkt, meta); } catch (_) {} });
    // 全体購読 ('*')
    const all = subs.get('*');
    if (all) all.forEach(cb => { try { cb(line, pkt, meta); } catch (_) {} });
  }

  global.RouterCapture = { subscribe, unsubscribe, emit, decode, decodeTree, format };
})(window);
