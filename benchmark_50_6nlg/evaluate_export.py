"""Export all parsing/IR JSON, compare exact semantic facts against scenario gold."""
import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def parser_facts(p):
    out=[('hostname',p['hostname'])]
    for r in p['static_routes']:
        import ipaddress
        out.append(('static',f"{ipaddress.IPv4Network(r['destination']+'/'+r['mask'], strict=False)}|{r['next_hop']}"))
    for r in p['ospf_processes']:
        out += [('ospf_id',r['process_id']),('ospf_router_id',r['router_id'])]
        out += [('ospf_network',f"{x['network']}|{x['wildcard_mask']}|{x['area']}") for x in r['networks']]
    for r in p['bgp_processes']:
        out.append(('bgp_as',r['local_as']))
        out += [('bgp_peer',f"{x['id']}|{x['remote_as']}") for x in r['neighbors']]
        out += [('bgp_network',f"{x['prefix']}/{__import__('ipaddress').IPv4Network('0.0.0.0/'+x['mask']).prefixlen}") for x in r['network_statements']]
    for r in p['eigrp_processes']:
        out.append(('eigrp_as',r['identifier']))
        out += [('eigrp_network','|'.join(x)) for x in r['networks']]
    for a in p['access_lists']:
        out.append(('acl_name',a['name']))
        if a['name'].startswith('FILTER_'):
            out.append(('acl_entries',len(a['entries'])))
    if p['nat_rules']:
        out.append(('nat_rules',len(p['nat_rules'])))
    out += [('nat_inside',x['name']) for x in p['interfaces'] if x.get('nat_role')=='inside']
    out += [('nat_outside',x['name']) for x in p['interfaces'] if x.get('nat_role')=='outside']
    for x in p['dhcp_pools']:
        out.append(('dhcp_pool',x['name']))
        if x.get('network'):
            import ipaddress
            q=x['network']; out.append(('dhcp_network',str(ipaddress.IPv4Network(q['address']+'/'+q['mask_or_prefix'],strict=False))))
        out += [('dhcp_gateway',g) for g in x['default_routers']]
    out += [('vrf_name',v['name']) for v in p['vrfs']]
    out += [('vlan_id',int(v['name'])) for v in p['vlans']]
    out += [('prefix_name',x['name']) for x in p['prefix_lists']]
    out += [('route_map_name',x['name']) for x in p['route_maps']]
    return [(k,str(v)) for k,v in out if v is not None]


def ir_facts(ir):
    out=[('hostname',ir['device']['hostname'])]
    for x in ir['routing']['static_routes']:
        out.append(('static',f"{x['prefix']}|{x['next_hop']}"))
    for x in ir['routing']['ospf']:
        out += [('ospf_id',x['process_id']),('ospf_router_id',x['router_id'])]
        out += [('ospf_network',f"{v['address']}|{v['wildcard']}|{v['area']}") for v in x['network_selectors']]
    for x in ir['routing']['bgp']:
        out.append(('bgp_as',x['local_as']))
        out += [('bgp_peer',f"{v['id']}|{v['remote_as']}") for v in x['neighbors']]
        out += [('bgp_network',v['prefix']) for v in x['network_statements']]
    for x in ir['routing']['eigrp']:
        out.append(('eigrp_as',x['identifier']))
        out += [('eigrp_network','|'.join(v)) for v in x['networks']]
    for x in ir['policies']['acls']:
        out.append(('acl_name',x['name']))
        if x['name'].startswith('FILTER_'):
            out.append(('acl_entries',len(x['entries'])))
    if ir['services']['nat']['rules']:
        out.append(('nat_rules',len(ir['services']['nat']['rules'])))
    out += [('nat_inside',x['name']) for x in ir['interfaces'] if x.get('nat_role')=='inside']
    out += [('nat_outside',x['name']) for x in ir['interfaces'] if x.get('nat_role')=='outside']
    for x in ir['services']['dhcp']['pools']:
        out.append(('dhcp_pool',x['name']))
        if x.get('subnet'):out.append(('dhcp_network',x['subnet']))
        out += [('dhcp_gateway',g) for g in x['gateways']]
    out += [('vrf_name',v['name']) for v in ir['vrfs']]
    out += [('vlan_id',v['id']) for v in ir['services']['vlans']]
    out += [('prefix_name',v['name']) for v in ir['policies']['prefix_lists']]
    out += [('route_map_name',v['name']) for v in ir['policies']['route_maps']]
    return [(k,str(v)) for k,v in out if v is not None]


def counts(ref, observed):
    a,b=Counter(map(tuple,ref)),Counter(map(tuple,observed))
    return sum((a&b).values()),sum((b-a).values()),sum((a-b).values()),list((a-b).elements()),list((b-a).elements())


def metrics(tp,fp,fn):
    p=tp/(tp+fp) if tp+fp else 1
    r=tp/(tp+fn) if tp+fn else 1
    return {'tp':tp,'fp':fp,'fn':fn,'precision':p,'recall':r,'f1':2*p*r/(p+r) if p+r else 0}


def main():
    cli=argparse.ArgumentParser()
    cli.add_argument('--project',required=True,type=Path)
    args=cli.parse_args()
    sys.path[:0]=[str(args.project.resolve()),str((args.project/'parsers').resolve())]
    from cisco_parser import parse_cisco_ios
    from normalizers.cisco_normalizer import normalize_cisco_ios
    for name in ('parsing','ir'):
        (ROOT/'export'/name).mkdir(parents=True,exist_ok=True)
    groups=defaultdict(lambda:[0,0,0])
    details=[]
    for cfg in sorted((ROOT/'configs').glob('*.cfg')):
        raw=cfg.read_bytes()
        reference=json.loads((ROOT/'gold'/f'{cfg.stem}.json').read_text())
        parsed=parse_cisco_ios(raw.decode('utf-8-sig'))
        ir=normalize_cisco_ios(parsed,source_file=cfg.name,sha256=hashlib.sha256(raw).hexdigest())
        for stage,model,extract in [('parsing',parsed,parser_facts),('ir',ir,ir_facts)]:
            (ROOT/'export'/stage/f'{cfg.stem}.{stage}.json').write_text(json.dumps(model,indent=2,ensure_ascii=False)+'\n')
            tp,fp,fn,missed,invented=counts(reference['facts'],extract(model))
            for i,v in enumerate((tp,fp,fn)):
                groups[(reference['family'],stage)][i]+=v
                groups[('TOTAL',stage)][i]+=v
            details.append({'config':cfg.name,'family':reference['family'],'stage':stage,
                            **metrics(tp,fp,fn),'missed':missed,'invented':invented})
    summary={}
    for (family,stage),(tp,fp,fn) in sorted(groups.items()):
        summary.setdefault(family,{})[stage]=metrics(tp,fp,fn)
    (ROOT/'details.json').write_text(json.dumps(details,indent=2)+'\n')
    (ROOT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    for family,stages in summary.items():
        print(family, ' | '.join(f"{stage}: TP={m['tp']} FP={m['fp']} FN={m['fn']} F1={m['f1']:.1%}" for stage,m in stages.items()))
    print('Exported 50 parsing JSON and 50 IR JSON')

if __name__=='__main__':main()
