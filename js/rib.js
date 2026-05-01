/**
 * RouterRib – Administrative Distance によるルート選択ユーティリティ
 *
 * 各 OS の show route ハンドラから呼ばれる。
 * candidates 配列を受け取り、プレフィックスごとに最小 AD (同 AD なら最小 metric) の
 * ルートのみを残した配列を返す。ECMP（同 AD・同 metric）は複数エントリを残す。
 *
 * candidate オブジェクト形式:
 *   { type: 'C'|'L'|'S'|'B', prefix: string, prefixLen: number,
 *     ad: number, metric: number, nexthop?: string, via?: string, ...any }
 *
 * デフォルト AD:
 *   Connected (C): 0   Local (L): 0   Static (S): 1   eBGP (B): 20
 */
window.RouterRib = (() => {
  'use strict';

  const AD = { C: 0, L: 0, S: 1, B: 20 };

  /**
   * candidates[] を受け取り、AD 選択後の best-route 配列を返す。
   * 結果はプレフィックス (辞書順) でソートされる。
   */
  function selectBest(candidates) {
    const groups = new Map();
    for (const r of candidates) {
      const key = `${r.prefix}/${r.prefixLen}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(r);
    }

    const winners = [];
    for (const [, routes] of groups) {
      // 最小 AD → 最小 metric の順にソート
      routes.sort((a, b) => (a.ad - b.ad) || (a.metric - b.metric));
      const bestAd     = routes[0].ad;
      const bestMetric = routes[0].metric;
      // 同 AD・同 metric のエントリをすべて採用 (ECMP)
      const best = routes.filter(r => r.ad === bestAd && r.metric === bestMetric);
      winners.push(...best);
    }

    // プレフィックスで辞書ソート（IP を数値比較）
    winners.sort((a, b) => {
      const toN = ip => ip.split('.').reduce((acc, o) => (acc * 256) + Number(o), 0);
      const na = toN(a.prefix), nb = toN(b.prefix);
      if (na !== nb) return na - nb;
      return (a.prefixLen - b.prefixLen) || (a.ad - b.ad);
    });

    return winners;
  }

  return { AD, selectBest };
})();
