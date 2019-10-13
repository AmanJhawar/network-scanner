#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from pip._internal import main as pipmain
pipmain(['install', 'netifaces'])
pipmain(['install', 'python-nmap'])

import netifaces, nmap
import socket, ipaddress, sqlite3
from uuid import getnode 
from datetime import datetime


''' START OF SQLite DATABASE '''
def db_connect(db_name):
    
    conn = sqlite3.connect(db_name)
    return conn

def table(conn, create_table):
    
    try:
        c = conn.cursor()
        c.execute(create_table)
    except Error as e:
        if(CONF & 1):
            print(e)
            
def db_create():
    
    #query preparation
    sql_ip = """CREATE TABLE IF NOT EXISTS ip (
                                        id integer PRIMARY KEY AUTOINCREMENT,
                                        ip text,
                                        system text,
                                        mac text,
                                        date_added text,
                                        date_modified text,
                                        status integer DEFAULT 0 NOT NULL
                                    );"""
 
    sql_port = """CREATE TABLE IF NOT EXISTS port (
                                        id integer PRIMARY KEY AUTOINCREMENT,
                                        ip_id integer,
                                        ports integer,
                                        service text,
                                        product text,
                                        version text,
                                        date_added text,
                                        date_modified text,
                                        status integer DEFAULT 0 NOT NULL,
                                        FOREIGN KEY (ip_id) REFERENCES ip (id)
                                    );"""
    conn = db_connect(db_name)
    c = conn.cursor()
    c.execute("PRAGMA foreign_keys = 1")

    if conn is not None:
        table(conn, sql_ip)
        table(conn, sql_port)
    else:
        if(CONF & 1):
            print("Error! cannot create the database connection.")
    conn.close()
    
def db_add(table, columns, values):

    st = 'INSERT INTO ' + table
    st += ' ('
    for i in range(len(columns)):
        st += str(columns[i])
        if(i != len(columns)-1):
            st += ', '
    
    st += ')'
    
    st += ' VALUES '
    st += '('
    for i in range(len(values)):
        st += '?'
        if(i != len(values)-1):
            st += ', '
    
    st += ')'
    
    conn = db_connect(db_name)
    c = conn.cursor()
    c.execute(st, values)
    conn.commit()
    conn.close()
    
def db_fetch(table, columns, where):
    
    conn = db_connect(db_name)
    c = conn.cursor()
    st = "SELECT "
    for i in range(len(columns)):
        st += str(columns[i])
        if(i != len(columns)-1):
            st += ', '
            
    st += ' FROM ' + table
    if(where):
        st += ' WHERE ' + where
        
    c = c.execute(st)
    s = c.fetchall()
    conn.close()
    return (s)

def db_update(table, columns, values, where):
    st = 'UPDATE ' + table
    st += ' SET '
    for i in range(len(columns)):
        st += str(columns[i])
        st += ' = ?'
        if(i != len(columns)-1):
            st += ', '
    if(where):
        st += ' WHERE ' + where
    
    conn = db_connect(db_name)
    c = conn.cursor()
    if(where):
        c.execute(st, values)

''' END OF SQLite DATABASE '''



''' START OF NETWORKING '''
def get_nd():
    
    for iface in netifaces.interfaces():
        iface_details = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in iface_details:
            for ip_interfaces in iface_details[netifaces.AF_INET]:
                for key, ip_add in ip_interfaces.items():
                    if key == 'addr' and ip_add != '127.0.0.1':
                        local_ip= (ip_add)
                    if key == 'netmask' and ip_add != '255.0.0.0':
                        subnet= (ip_add)
    net = ipaddress.IPv4Network(local_ip + '/' + subnet, False)
    return [local_ip, subnet, net]

def accurate_scan(nm, net):

    #ping scan code needs to be here
    ip_list = []
    nm.scan(hosts=str(net), arguments = '-n -sn -PE -PA21,23,80,3389 --min-parallelism 100')
    
    for host in nm.all_hosts():
        try:
            mac = nm[host]['addresses']['mac']
        except:
            add = getnode()
            h = iter(hex(add)[2:].zfill(12))
            mac = ":".join(i + next(h) for i in h)
        #host_name = nm[host].hostname()
        ip_mac = {mac : host}
        if(CONF & 1):
            print('DEBUG [accurate_scan]> %s' % ip_mac)
        ip_list.append(ip_mac)
    return ip_list

def port_scan(nm, ip, cmd):
    scan_list = []
    nm.scan(hosts=ip, arguments=cmd)
    # add -T5 in the arguments above for faster execution
    
    for host in nm.all_hosts():
        if(CONF & 1):
            print('----------------------------------------')
            print('Host: %s' % (host))
        for x in nm[host].all_protocols():
            port = list(nm[host][x].keys())
            port.sort()
            
            for y in port:
                serv = nm[host][x][y]['name']
                if(nm[host][x][y]['version'])!='':
                    ver=nm[host][x][y]['version']
                else:
                    ver='----'
                    
                if(nm[host][x][y]['product'])!='':
                    prod=nm[host][x][y]['product']
                else:
                    prod='----'
                    
                values = (y, serv, prod, ver)
                scan_list.append(values)
        return scan_list

''' END OF NETWORKING '''


''' 0x00 0x00 0000 0001 = DEBUG '''
''' 0x00 0x00 0000 0010 = ACCURATE IP SCAN ''' 
''' 0x00 0x00 0000 1000 = FAST PORT & SERVICE SCAN FOR SMALL NETWORK '''
''' 0x00 0x00 0001 0000 = FAST PORT & SERVICE SCAN FOR BIG NETWORK '''
''' 0x00 0x00 0010 0000 = ACCURATE PORT & SERVICE SCAN FOR SMALL NETWORK '''
''' 0x00 0x00 0100 0000 = ACCURATE PORT & SERVICE SCAN FOR BIG NETWORK '''
''' 0x00 0x00 1000 0000 = VERSION & PRODUCT OF SERVICE '''


def main():
    
    global CONF, db_name
    db_name = 'sql.db'
    CONF = 131
    ''' CONF = CONF ^ 1 '''
    
    ''' DEFAULT START'''
    cmd='-n '

    if(CONF & 8):
        cmd = cmd + '--script=dns-service-discovery '
        
    if(CONF & 16):
        cmd = cmd + '--script=dns-service-discovery --min-parallelism 100 -T5 '
        
    if(CONF & 32):
        cmd = cmd + '--script=dns-service-discovery --min-parallelism 100 '
        
    if(CONF & 64):
        cmd = cmd + '--script=dns-service-discovery -sc-min-parallelism 100 -T5 '
    
    if(CONF & 128):
        cmd = cmd + '-sV '

    ''' DEFAULT END'''
    cmd = cmd + '-Pn '
    
    if(CONF & 1):
        print(cmd)
        
    db_create()
    network_details = get_nd()
    local_ip, subnet, net = network_details[0], network_details[1], network_details[2]
    
    print(net, local_ip, subnet)
    nm = nmap.PortScanner()

    if(CONF & 2):
        ip_list = accurate_scan(nm, net)
        
    now = datetime.now()
    r = datetime.timestamp(now)
    #list_mac = db_fetch('ip', ['ip', 'mac'], 'mac = "' +mac+'"')
    list_mac = db_fetch('ip', ['ip', 'mac'], '')
    out = dict(list_mac)
    
    for i in ip_list:
        for j, k in (i.items()):
            mac, ip = j, k
            
        if(mac in out.values() and ip not in out.keys()):
            value = (ip, mac, r, r)
            db_add('ip', ['ip', 'mac', 'date_added', 'date_modified'], value)
            
        elif(mac not in out.values()):
            value = (ip, mac, r, r)
            db_add('ip', ['ip', 'mac', 'date_added', 'date_modified'], value)
        
        elif(mac in out.values() and ip in out.keys()):
            db_update('ip', ['date_modified'], 'r', 'mac = "' +mac+'"')
        
    list_ip = db_fetch('ip', ['id', 'ip'], '')
    list_ip = dict(list_ip)
    port_list = db_fetch('port', ['ip_id', 'ports'], '')
    ip_id_list = [ i for i, j in port_list ]
    
    for i, j in (list_ip.items()):
        ip_id, ip = i, j
        scan_list = port_scan(nm, ip, cmd)
        service_list = []
        for k in port_list:
            if(k[0] == ip_id):
                service_list.append(k[1])
    
        if(scan_list):
            for k in scan_list:
                port, service, product, version = k[0], k[1], k[2], k[3]
                values = (ip_id, port, service, product, version, r, r)
                if(ip_id in ip_id_list):
                    if(port not in service_list):
                        db_add('port', ['ip_id', 'ports', 'service', 'product', 'version', 'date_added', 'date_modified'], values)
                        
                    elif(port in service_list):
                        p = str(port)
                        db_update('port', ['date_modified'], 'r', 'ports = "' +p+'"')
                        
                elif(ip_id not in ip_id_list):
                    db_add('port', ['ip_id', 'ports', 'service', 'product', 'version', 'date_added', 'date_modified'], values)
                        
                if(CONF & 1):
                    print('Port: %s \t Service: %s \t Product: %s \t Version: %s' % (port, service, product, version))


if __name__ == '__main__':
    
    main()

