// ネットワークトポロジー定義（ロジックなし・データのみ）
// 各ノードは仮想ルータを表す。os は 'ios-xe' | 'ios-xr'。
// links は両端のノードIDを ports と共に持つ。
window.TOPOLOGY = {
  nodes: [
    {
      id: 'R1',
      hostname: 'R1-XE',
      os: 'ios-xe',
      x: 120, y: 120,
      defaultConfig:
        'hostname R1-XE\n' +
        'interface GigabitEthernet0/0\n' +
        ' ip address 10.0.12.1 255.255.255.0\n' +
        ' description link to R2\n' +
        '!\n' +
        'interface Loopback0\n' +
        ' ip address 1.1.1.1 255.255.255.255\n' +
        '!\n',
    },
    {
      id: 'R2',
      hostname: 'R2-XR',
      os: 'ios-xr',
      x: 380, y: 120,
      defaultConfig:
        'hostname R2-XR\n' +
        'interface GigabitEthernet0/0\n' +
        ' ipv4 address 10.0.12.2/24\n' +
        ' description link to R1\n' +
        '!\n' +
        'interface Loopback0\n' +
        ' ipv4 address 2.2.2.2/32\n' +
        '!\n',
    },
    {
      id: 'R3',
      hostname: 'R3-XE',
      os: 'ios-xe',
      x: 250, y: 280,
      defaultConfig:
        'hostname R3-XE\n' +
        'interface GigabitEthernet0/0\n' +
        ' ip address 10.0.23.3 255.255.255.0\n' +
        ' description link to R2\n' +
        '!\n',
    },
  ],
  links: [
    { a: 'R1', b: 'R2', aPort: 'Gi0/0', bPort: 'Gi0/0' },
    { a: 'R2', b: 'R3', aPort: 'Gi0/1', bPort: 'Gi0/0' },
  ],
};
