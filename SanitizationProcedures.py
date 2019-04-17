import hashlib
import urllib.parse
import re
import glob
import json


def convert(string):
    hash = hashlib.md5()
    hash.update(bytes(string, encoding='utf-8'))
    return hash.hexdigest()[:8]



def sanitize(value):
    normals = value.lower().replace('\\', ' ').split(' ')
    hashed_components = []
    for normal in normals:
        hashed_components = hashed_components+[convert(normal)]
    return ' '.join(hashed_components)

def sanitize_file(filename):
    normals = filename.lower().replace('\\', ' ').replace('.',' ').split(' ')
    hashed_components = []
    for normal in normals[-3:]:
        hashed_components = hashed_components+[convert(normal)]
    return ' '.join(hashed_components)


def sanitize_reg(keyname):
    normals = keyname.lower().replace('\\', ' ').split(' ')
    hashed_components = []
    for normal in normals[-2:]:
        hashed_components = hashed_components+[convert(normal)]
    return ' '.join(hashed_components)


def sanitize_cmd(cmd):
    normals = cmd.lower().replace('"', ' ').replace('\\', ' ').replace('.',' ').split(' ')
    hash = hashlib.md5()
    hashed_components = []
    for normal in normals:
        hash.update(bytes(normal, encoding='utf-8'))
        hashed_components = hashed_components+[hash.hexdigest()[:8]]
    return ' '.join(hashed_components)


def sanitize_generic(value):
    value = value.lower()
    return convert(value)


def sanitize_domain(domain):
    components = domain.lower().split('.')
    hash = hashlib.md5()
    hashed_components = []
    for comp in components:
        hash.update(bytes(comp, encoding='utf-8'))
        hashed_components = hashed_components + [hash.hexdigest()[:8]]
    return ' '.join(hashed_components)


def sanitize_ip(ipaddr):
    components = ipaddr.split('.')
    class_c = components[:3]
    hash = hashlib.md5()
    hashed_components = []
    hash.update(bytes('.'.join(class_c), encoding='utf-8'))
    hashed_components = hashed_components + [hash.hexdigest()[:8]]
    hash.update(bytes(ipaddr, encoding='utf-8'))
    hashed_components = hashed_components + [hash.hexdigest()[:8]]
    return ' '.join(hashed_components)


def sanitize_url(url):
    uri = url
    if  ":" in url:
        uri = url[url.index(":")+1:]
    uri = uri.strip("/")
    quoted = urllib.parse.quote_plus(uri.encode()).lower()
    hash = hashlib.md5()
    hashed_components = []
    hash.update(bytes(quoted, encoding='utf-8'))
    hashed_components = hashed_components + [hash.hexdigest()[:8]]
    return hashed_components



if __name__ == '__main__':
    #定义变量
    save_dict = dict()
    pe_sec_name = ""
    pe_sec_entropy = ""
    pe_sec_character = ""
    pe_imports = ""
    file_delete = ""
    file_read = ""
    file_drop = ""
    file_write = ""
    reg_access = ""
    reg_delete = ""
    reg_read = ""
    reg_write = ""
    string = ""
    cmd_exec = ""
    api_resolv = ""
    save_dict['properties'] = {}

    #定义路径
    dir = "C:\\Users\\Bitter\\Desktop\\18\\reports"
    file = dir + "\\report.json"
    file = open(file)
    load_dict = json.load(file)


    #file
    for i in range(len(load_dict['behavior']['summary']['file_written'])):
        s = load_dict['behavior']['summary']['file_written'][i]
        file_write = file_write + " " + sanitize_file(s)

    for i in range(len(load_dict['behavior']['summary']['file_deleted'])):
        s = load_dict['behavior']['summary']['file_deleted'][i]
        file_delete = file_delete + " " + sanitize_file(s)

    for i in range(len(load_dict['behavior']['summary']['file_read'])):
        s = load_dict['behavior']['summary']['file_read'][i]
        file_read = file_read + " " + sanitize_file(s)

    for i in range(len(load_dict['behavior']['summary']['file_failed'])):
        s = load_dict['behavior']['summary']['file_failed'][i]
        file_drop = file_drop + " " + sanitize_file(s)

    #regkey
    for i in range(len(load_dict['behavior']['summary']['regkey_deleted'])):
        s = load_dict['behavior']['summary']['regkey_deleted'][i]
        reg_delete = reg_delete + " " + sanitize_reg(s)

    for i in range(len(load_dict['behavior']['summary']['regkey_read'])):
        s = load_dict['behavior']['summary']['regkey_read'][i]
        reg_read = reg_read + " " + sanitize_reg(s)


    for i in range(len(load_dict['behavior']['summary']['regkey_written'])):
        s = load_dict['behavior']['summary']['regkey_written'][i]
        reg_write = reg_write + " " + sanitize_reg(s)



    #pe
    for i in range(len(load_dict['static']['pe_sections'])):
        name = load_dict['static']['pe_sections'][i]['name']
        pe_sec_name =pe_sec_name  + " " + sanitize(name)

        entropy = str(load_dict['static']['pe_sections'][i]['entropy'])
        pe_sec_entropy =  pe_sec_entropy + " " + sanitize(entropy)

        virtual_size = str(load_dict['static']['pe_sections'][i]['virtual_size'])
        pe_sec_character = pe_sec_character  + " " + sanitize(virtual_size)

    for i in range(len(load_dict['static']['pe_imports'])):
        for j in range(len(load_dict['static']['pe_imports'][i]['imports'])):
            name = load_dict['static']['pe_imports'][i]['imports'][j]['name']
            pe_imports = pe_imports +  " " +  sanitize(name)


    #cmd
    for i in range(len(load_dict['behavior']['summary']['command_line'])):
        cmd = load_dict['behavior']['summary']['command_line'][i]
        cmd_exec = cmd_exec + " " + sanitize_cmd(cmd)


    #string
    for i in range(len(load_dict['strings'])):
        s = load_dict['strings'][i]
        string = string + " " + sanitize_generic(s)

    #api
    for key in load_dict['behavior']['apistats']:
        for key in load_dict['behavior']['apistats'][key]:
            api_resolv = api_resolv + " " + sanitize_generic(key)

    #保存
    save_dict['properties']['pe_sec_entropy'] = pe_sec_entropy[1:]
    save_dict['properties']['pe_sec_name'] = pe_sec_name[1:]
    save_dict['properties']['pe_sec_character'] = pe_sec_character[1:]
    save_dict['properties']['pe_imports'] = pe_imports[1:]
    save_dict['properties']['reg_read'] = reg_read[1:]
    save_dict['properties']['reg_write'] = reg_write[1:]
    save_dict['properties']['reg_delete'] = reg_delete[1:]
    save_dict['properties']['file_delete'] = file_delete[1:]
    save_dict['properties']['file_read'] = file_read[1:]
    save_dict['properties']['file_write'] = file_write[1:]
    save_dict['properties']['file_drop'] = file_drop[1:]
    save_dict['properties']['str'] = string[1:]
    save_dict['properties']['cmd_exec'] = cmd_exec[1:]
    save_dict['properties']['api_resolv'] = api_resolv[1:]





    with open(dir + "\\toMIST1.json", 'w') as save_json:
        json.dump(save_dict, save_json)
        save_json.close()
    print("yes")