// Wireshark 互換ディスプレイフィルタ コンパイラ & 評価器。
// 公開: RouterCaptureFilter = { compile(expr) }
//   compile(expr) -> { ok: true,  fn: (bytes: Uint8Array) -> bool }
//               or -> { ok: false, error: string }
//
// サポートフィールド:
//   プロトコル : arp  ip  tcp  udp  icmp  bgp  ospf  eth
//   Ethernet   : eth.src  eth.dst  eth.addr  eth.type  frame.len
//   ARP        : arp.opcode  arp.src.proto_ipv4  arp.dst.proto_ipv4
//                arp.src.hw_mac  arp.dst.hw_mac
//   IP         : ip.src  ip.dst  ip.addr  ip.proto  ip.ttl  ip.len
//   TCP        : tcp.srcport  tcp.dstport  tcp.port  tcp.seq  tcp.ack
//                tcp.flags  tcp.flags.syn  tcp.flags.ack  tcp.flags.rst
//                tcp.flags.fin  tcp.flags.push  tcp.flags.urg
//   UDP        : udp.srcport  udp.dstport  udp.port  udp.length
//   ICMP       : icmp.type  icmp.code
//   BGP        : bgp.type
//   OSPF       : ospf.msg
//
// 演算子 : ==  !=  >  <  >=  <=  contains
// 論理   : &&  ||  !  and  or  not
// グループ: ( )
(function (global) {
  'use strict';

  // ---- Tokenizer ----

  const T = { IDENT: 'IDENT', NUM: 'NUM', STR: 'STR', OP: 'OP', LP: 'LP', RP: 'RP', EOF: 'EOF' };

  function tokenize(src) {
    const toks = [];
    let i = 0;
    while (i < src.length) {
      if (/\s/.test(src[i])) { i++; continue; }
      // 2-char operators
      const two = src.slice(i, i + 2);
      if (['==', '!=', '>=', '<=', '&&', '||'].includes(two)) {
        toks.push({ t: T.OP, v: two }); i += 2; continue;
      }
      if ('!><'.includes(src[i])) { toks.push({ t: T.OP, v: src[i] }); i++; continue; }
      if (src[i] === '(') { toks.push({ t: T.LP }); i++; continue; }
      if (src[i] === ')') { toks.push({ t: T.RP }); i++; continue; }
      // string literal
      if (src[i] === '"' || src[i] === "'") {
        const q = src[i++];
        let s = '';
        while (i < src.length && src[i] !== q) s += src[i++];
        i++;
        toks.push({ t: T.STR, v: s }); continue;
      }
      // word: identifier, dotted field, number, IP, MAC
      if (/[\w]/.test(src[i])) {
        let s = '';
        while (i < src.length && /[\w.:/-]/.test(src[i])) s += src[i++];
        if (/^0x[\da-fA-F]+$/.test(s)) {
          toks.push({ t: T.NUM, v: parseInt(s, 16) });
        } else if (/^\d+$/.test(s)) {
          toks.push({ t: T.NUM, v: parseInt(s, 10) });
        } else if (/^\d+\.\d+\.\d+\.\d+$/.test(s) || /^[\da-fA-F]{2}(:[\da-fA-F]{2}){5}$/.test(s)) {
          // IP or MAC -> string value
          toks.push({ t: T.STR, v: s });
        } else {
          toks.push({ t: T.IDENT, v: s });
        }
        continue;
      }
      throw new Error(`Unexpected char: '${src[i]}'`);
    }
    toks.push({ t: T.EOF });
    return toks;
  }

  // ---- Recursive Descent Parser ----
  // expr     = or
  // or       = and  (('||'|'or')  and)*
  // and      = not  (('&&'|'and') not)*
  // not      = ('!'|'not') not | paren
  // paren    = '(' expr ')' | atom
  // atom     = IDENT cmpop value | IDENT   (protocol)
  // cmpop    = '=='|'!='|'>'|'<'|'>='|'<='|'contains'|'matches'
  // value    = NUM | STR | IDENT

  function parse(toks) {
    let pos = 0;
    const peek = () => toks[pos];
    const eat  = () => toks[pos++];

    function parseExpr() { return parseOr(); }

    function parseOr() {
      let n = parseAnd();
      while ((peek().t === T.OP && peek().v === '||') ||
             (peek().t === T.IDENT && peek().v === 'or')) {
        eat();
        n = { op: 'or', l: n, r: parseAnd() };
      }
      return n;
    }

    function parseAnd() {
      let n = parseNot();
      while ((peek().t === T.OP && peek().v === '&&') ||
             (peek().t === T.IDENT && peek().v === 'and')) {
        eat();
        n = { op: 'and', l: n, r: parseNot() };
      }
      return n;
    }

    function parseNot() {
      if ((peek().t === T.OP && peek().v === '!') ||
          (peek().t === T.IDENT && peek().v === 'not')) {
        eat();
        return { op: 'not', x: parseNot() };
      }
      return parseParen();
    }

    function parseParen() {
      if (peek().t === T.LP) {
        eat();
        const n = parseExpr();
        if (peek().t !== T.RP) throw new Error("Expected ')'");
        eat();
        return n;
      }
      return parseAtom();
    }

    function parseAtom() {
      const t = peek();
      if (t.t !== T.IDENT) throw new Error(`Expected field name, got: ${JSON.stringify(t)}`);
      eat();
      const field = t.v;
      // look-ahead: is there a comparison operator?
      const nx = peek();
      const isCmpOp = (nx.t === T.OP) ||
                      (nx.t === T.IDENT && (nx.v === 'contains' || nx.v === 'matches'));
      if (isCmpOp) {
        const op = eat().v;
        const vt = peek();
        if (vt.t !== T.NUM && vt.t !== T.STR && vt.t !== T.IDENT)
          throw new Error(`Expected value after ${op}`);
        const val = eat().v;
        return { op: 'cmp', field, cmp: op, val };
      }
      // Just a protocol keyword
      return { op: 'proto', proto: field };
    }

    const ast = parseExpr();
    if (peek().t !== T.EOF) throw new Error(`Unexpected token: ${JSON.stringify(peek())}`);
    return ast;
  }

  // ---- Packet field extractor ----

  function u16(b, o) { return (b[o] << 8) | b[o + 1]; }
  function u32(b, o) { return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0; }
  function ip4(b, o) { return `${b[o]}.${b[o+1]}.${b[o+2]}.${b[o+3]}`; }
  function mac(b, o) { return [0,1,2,3,4,5].map(i => b[o+i].toString(16).padStart(2,'0')).join(':'); }

  function extractInfo(bytes) {
    const f = {};
    if (!bytes || bytes.length < 14) return f;

    f['eth.dst']   = mac(bytes, 0);
    f['eth.src']   = mac(bytes, 6);
    f['eth.type']  = u16(bytes, 12);
    f['frame.len'] = bytes.length;

    const et = f['eth.type'];

    if (et === 0x0806) {
      f._proto = 'arp';
      f['arp.opcode']            = u16(bytes, 20);
      f['arp.src.hw_mac']        = mac(bytes, 22);
      f['arp.src.proto_ipv4']    = ip4(bytes, 28);
      f['arp.dst.hw_mac']        = mac(bytes, 32);
      f['arp.dst.proto_ipv4']    = ip4(bytes, 38);
    } else if (et === 0x0800) {
      if (bytes.length < 20) return f;
      const ihl = (bytes[14] & 0x0f) * 4;
      const proto = bytes[14 + 9];
      f['ip.src']   = ip4(bytes, 14 + 12);
      f['ip.dst']   = ip4(bytes, 14 + 16);
      f['ip.proto'] = proto;
      f['ip.ttl']   = bytes[14 + 8];
      f['ip.len']   = u16(bytes, 14 + 2);
      f._proto = 'ip';

      const toff = 14 + ihl;
      if (proto === 1 && toff + 4 <= bytes.length) {
        f._proto       = 'icmp';
        f['icmp.type'] = bytes[toff];
        f['icmp.code'] = bytes[toff + 1];
      } else if (proto === 6 && toff + 14 <= bytes.length) {
        f._proto          = 'tcp';
        f['tcp.srcport']  = u16(bytes, toff);
        f['tcp.dstport']  = u16(bytes, toff + 2);
        f['tcp.port']     = [f['tcp.srcport'], f['tcp.dstport']];
        f['tcp.seq']      = u32(bytes, toff + 4);
        f['tcp.ack']      = u32(bytes, toff + 8);
        const flags       = bytes[toff + 13];
        f['tcp.flags']        = flags;
        f['tcp.flags.fin']    = (flags & 0x01) ? 1 : 0;
        f['tcp.flags.syn']    = (flags & 0x02) ? 1 : 0;
        f['tcp.flags.rst']    = (flags & 0x04) ? 1 : 0;
        f['tcp.flags.push']   = (flags & 0x08) ? 1 : 0;
        f['tcp.flags.ack']    = (flags & 0x10) ? 1 : 0;
        f['tcp.flags.urg']    = (flags & 0x20) ? 1 : 0;
        // BGP detection
        const doff = (bytes[toff + 12] >> 4) * 4;
        if ((f['tcp.srcport'] === 179 || f['tcp.dstport'] === 179) &&
            toff + doff + 19 <= bytes.length) {
          let bgp = true;
          for (let i = 0; i < 16; i++) if (bytes[toff + doff + i] !== 0xff) { bgp = false; break; }
          if (bgp) {
            f._proto     = 'bgp';
            f['bgp.type'] = bytes[toff + doff + 18];
          }
        }
      } else if (proto === 17 && toff + 8 <= bytes.length) {
        f._proto          = 'udp';
        f['udp.srcport']  = u16(bytes, toff);
        f['udp.dstport']  = u16(bytes, toff + 2);
        f['udp.port']     = [f['udp.srcport'], f['udp.dstport']];
        f['udp.length']   = u16(bytes, toff + 4);
      } else if (proto === 89 && toff + 2 <= bytes.length) {
        f._proto      = 'ospf';
        f['ospf.msg'] = bytes[toff + 1];
      }
    }
    return f;
  }

  // ---- Evaluator ----

  function evaluate(node, f) {
    switch (node.op) {
      case 'or':   return evaluate(node.l, f) || evaluate(node.r, f);
      case 'and':  return evaluate(node.l, f) && evaluate(node.r, f);
      case 'not':  return !evaluate(node.x, f);
      case 'proto': return matchProto(node.proto, f);
      case 'cmp':  return matchCmp(node.field, node.cmp, node.val, f);
      default: return false;
    }
  }

  function matchProto(proto, f) {
    const p = f._proto || '';
    switch (proto) {
      case 'eth':  return true;
      case 'arp':  return p === 'arp';
      case 'ip':   return ['ip','tcp','udp','icmp','ospf','bgp'].includes(p);
      case 'tcp':  return p === 'tcp' || p === 'bgp';
      case 'udp':  return p === 'udp';
      case 'icmp': return p === 'icmp';
      case 'bgp':  return p === 'bgp';
      case 'ospf': return p === 'ospf';
      default: return false;
    }
  }

  function matchCmp(field, op, val, f) {
    if (field === 'ip.addr') return cmp(f['ip.src'], op, val) || cmp(f['ip.dst'], op, val);
    if (field === 'eth.addr') return cmp(f['eth.src'], op, val) || cmp(f['eth.dst'], op, val);
    const v = f[field];
    if (Array.isArray(v)) return v.some(x => cmp(x, op, val));
    return cmp(v, op, val);
  }

  function cmp(actual, op, expected) {
    if (actual === undefined || actual === null) return false;
    let exp = expected;
    if (typeof actual === 'number' && typeof exp === 'string') {
      const n = Number(exp);
      if (!isNaN(n)) exp = n;
    }
    switch (op) {
      case '==':       return actual == exp;
      case '!=':       return actual != exp;
      case '>':        return actual > exp;
      case '<':        return actual < exp;
      case '>=':       return actual >= exp;
      case '<=':       return actual <= exp;
      case 'contains': return String(actual).toLowerCase().includes(String(exp).toLowerCase());
      case 'matches':  try { return new RegExp(exp).test(String(actual)); } catch(_) { return false; }
      default: return false;
    }
  }

  // ---- Public API ----

  function compile(exprStr) {
    const s = (exprStr || '').trim();
    if (!s) return { ok: true, fn: () => true };
    try {
      const ast = parse(tokenize(s));
      return {
        ok: true,
        fn(bytes) {
          try { return evaluate(ast, extractInfo(bytes)); } catch (_) { return false; }
        },
      };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  global.RouterCaptureFilter = { compile };
})(window);
