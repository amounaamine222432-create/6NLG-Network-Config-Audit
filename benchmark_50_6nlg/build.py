"""Deterministic broad Cisco IOS 15 family corpus, with declarative gold facts."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FAMILIES = ['STATIC','OSPF','BGP','EIGRP','ACL','NAT','DHCP','VLAN_VRF','POLICY','MIXED']


def scenario(family, variant):
    n = variant
    h = f'R-{family}-{n:02d}'
    header = ['version 15.2', f'hostname {h}']
    facts = [('hostname', h)]
    def add(kind, value):
        facts.append((kind, str(value)))
    if family == 'STATIC':
        gateway = f'192.0.2.{n}'
        header += [f'ip route 10.{n}.0.0 255.255.255.0 {gateway}',
                   f'ip route 0.0.0.0 0.0.0.0 198.51.100.{n}']
        add('static', f'10.{n}.0.0/24|{gateway}')
        add('static', f'0.0.0.0/0|198.51.100.{n}')
    elif family == 'OSPF':
        header += [f'router ospf {n}', f' router-id 10.0.0.{n}',
                   f' network 10.{n}.0.0 0.0.255.255 area 0',
                   ' passive-interface GigabitEthernet0/1']
        add('ospf_id', n)
        add('ospf_router_id', f'10.0.0.{n}')
        add('ospf_network', f'10.{n}.0.0|0.0.255.255|0')
    elif family == 'BGP':
        header += [f'router bgp {65000+n}', f' bgp router-id 10.0.0.{n}',
                   f' neighbor 192.0.2.{n} remote-as {65100+n}',
                   f' network 10.{n}.0.0 mask 255.255.0.0']
        add('bgp_as', 65000+n)
        add('bgp_peer', f'192.0.2.{n}|{65100+n}')
        add('bgp_network', f'10.{n}.0.0/16')
    elif family == 'EIGRP':
        header += [f'router eigrp {n}', f' network 10.{n}.0.0 0.0.255.255',
                   ' no auto-summary']
        add('eigrp_as', n)
        add('eigrp_network', f'10.{n}.0.0|0.0.255.255')
    elif family == 'ACL':
        header += [f'ip access-list extended FILTER_{n}',
                   f' permit tcp 10.{n}.0.0 0.0.255.255 any eq 443',
                   ' deny ip any any log']
        add('acl_name', f'FILTER_{n}')
        add('acl_entries', 2)
    elif family == 'NAT':
        header += [f'ip nat inside source static 10.{n}.0.10 203.0.113.{n}',
                   'interface GigabitEthernet0/0', ' ip nat outside',
                   'interface GigabitEthernet0/1', ' ip nat inside']
        add('nat_rules', 1)
        add('nat_inside', 'GigabitEthernet0/1')
        add('nat_outside', 'GigabitEthernet0/0')
    elif family == 'DHCP':
        header += [f'ip dhcp excluded-address 10.{n}.0.1 10.{n}.0.10',
                   f'ip dhcp pool USERS_{n}', f' network 10.{n}.0.0 255.255.255.0',
                   f' default-router 10.{n}.0.1', ' dns-server 192.0.2.53']
        add('dhcp_pool', f'USERS_{n}')
        add('dhcp_network', f'10.{n}.0.0/24')
        add('dhcp_gateway', f'10.{n}.0.1')
    elif family == 'VLAN_VRF':
        header += [f'vrf definition CLIENT_{n}', f' rd 65000:{n}',
                   f'vlan {100+n}', f' name CLIENT_{n}',
                   'interface GigabitEthernet0/1', f' vrf forwarding CLIENT_{n}']
        add('vrf_name', f'CLIENT_{n}')
        add('vlan_id', 100+n)
    elif family == 'POLICY':
        header += [f'ip prefix-list PL_{n} seq 5 permit 10.{n}.0.0/16',
                   f'route-map RM_{n} permit 10', f' match ip address prefix-list PL_{n}']
        add('prefix_name', f'PL_{n}')
        add('route_map_name', f'RM_{n}')
    elif family == 'MIXED':
        header += [f'ip route 10.{n}.0.0 255.255.255.0 192.0.2.{n}',
                   f'ip dhcp pool LAN_{n}', f' network 10.{n}.0.0 255.255.255.0',
                   'interface GigabitEthernet0/1', f' ip address 10.{n}.0.1 255.255.255.0',
                   f'ip access-list standard MGMT_{n}', f' permit 192.0.2.{n}']
        add('static', f'10.{n}.0.0/24|192.0.2.{n}')
        add('dhcp_pool', f'LAN_{n}')
        add('dhcp_network', f'10.{n}.0.0/24')
        add('acl_name', f'MGMT_{n}')
    return '\n'.join(header+['end','']), facts


def main():
    (ROOT/'configs').mkdir(parents=True, exist_ok=True)
    (ROOT/'gold').mkdir(parents=True, exist_ok=True)
    manifest=[]
    for family in FAMILIES:
        for n in range(1,6):
            name=f'{family}_{n:02d}'
            text, facts=scenario(family,n)
            (ROOT/'configs'/f'{name}.cfg').write_text(text)
            (ROOT/'gold'/f'{name}.json').write_text(json.dumps({'family':family,'facts':facts},indent=2)+'\n')
            manifest.append({'name':name,'family':family,'facts':len(facts)})
    (ROOT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Created',len(manifest),'configs, gold reference files')

if __name__=='__main__':
    main()
