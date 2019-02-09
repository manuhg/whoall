import nmap
import os
import time
def filter_info(host):
    hostname = host[0]
    ad = host[1]['addresses']
    vendor = list(host[1]['vendor'].values())
    vendor = vendor[0] if vendor else '-'
    ad.update({'vendor':vendor})
    mac = ad.get('mac')
    ad['mac'] = mac if mac else '-'
    ad['ipv4'] = ad['ipv4'].ljust(12)
    return ad

def print_details(det_lst):
    print('\t\t'.join(list(det_lst[0].keys())))
    list(map(lambda p:print('\t'.join(list(p.values()))),det_lst))

def main():
    nma = nmap.PortScanner()
    print('Looking for gateway ip using arp..')
    gateway_ip = os.popen('arp -a | grep "gateway" | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}"').read()
    print('Found gateway ',gateway_ip)
    try:
        while(True):
            subnet ='.'.join(gateway_ip.split('.')[:-1]) +'.0/24'
            #print('Scanning network subnet',subnet)
            results = nma.scan(hosts=subnet,arguments='-n -sn')
            p_results = list(map(filter_info,list(results['scan'].items())))
            os.system('clear')
            print('Scanned network subnet',subnet)
            print_details(p_results)

    except KeyboardInterrupt:
        print('Ctrl-c pressed')
    print('Quitting...')

if __name__ == '__main__':
    main()
