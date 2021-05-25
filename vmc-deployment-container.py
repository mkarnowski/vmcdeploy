

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
import yaml
import logging
import traceback
import sys
import os
from datetime import datetime
import time
from netaddr import IPNetwork
import subprocess
import copy
import glob


#------ setup logging
#logging.basicConfig(filename='/var/log/avideployment.log', encoding='utf-8', level=logging.DEBUG)






#------- Ova Specs

controller_spec_template = {
  "IPAllocationPolicy": "dhcpPolicy",
  "IPProtocol": "IPv4",
  "PropertyMapping": [
    {
      "Key": "avi.mgmt-ip.CONTROLLER",
      "Value": ""
    },
    {
      "Key": "avi.mgmt-mask.CONTROLLER",
      "Value": ""
    },
    {
      "Key": "avi.default-gw.CONTROLLER",
      "Value": ""
    },
    {
      "Key": "avi.sysadmin-public-key.CONTROLLER",
      "Value": ""
    }
  ],
  "NetworkMapping": [
    {
      "Name": "Management",
      "Network": ""
    }
  ],
  "MarkAsTemplate": False,
  "PowerOn": False,
  "InjectOvfEnv": False,
  "WaitForIP": False,
  "Name": "avicontroller"
}



se_spec_template = {
  "IPAllocationPolicy": "dhcpPolicy",
  "IPProtocol": "IPv4",
  "PropertyMapping": [
    {
      "Key": "AVICNTRL",
      "Value": ""
    },
    {
      "Key": "AVISETYPE",
      "Value": "NETWORK_ADMIN"
    },
    {
      "Key": "AVICNTRL_AUTHTOKEN",
      "Value": ""
    },
    {
      "Key": "AVICNTRL_CLUSTERUUID",
      "Value": ""
    },
    {
      "Key": "avi.mgmt-ip.SE",
      "Value": ""
    },
    {
      "Key": "avi.mgmt-mask.SE",
      "Value": ""
    },
    {
      "Key": "avi.default-gw.SE",
      "Value": ""
    },
    {
      "Key": "avi.DNS.SE",
      "Value": ""
    },
    {
      "Key": "avi.sysadmin-public-key.SE",
      "Value": ""
    }
  ],
  "NetworkMapping": [
    {
      "Name": "Management",
      "Network": ""
    },
    {
      "Name": "Data Network 1",
      "Network": ""
    },
    {
      "Name": "Data Network 2",
      "Network": ""
    },
    {
      "Name": "Data Network 3",
      "Network": ""
    },
    {
      "Name": "Data Network 4",
      "Network": ""
    },
    {
      "Name": "Data Network 5",
      "Network": ""
    },
    {
      "Name": "Data Network 6",
      "Network": ""
    },
    {
      "Name": "Data Network 7",
      "Network": ""
    },
    {
      "Name": "Data Network 8",
      "Network": ""
    },
    {
      "Name": "Data Network 9",
      "Network": ""
    }
  ],
  "MarkAsTemplate": False,
  "PowerOn": False,
  "InjectOvfEnv": False,
  "WaitForIP": False,
  "Name": 'avise'
}

#------------------------------

def avi_login(avi_user, avi_pass):
    global login
    login = requests.post('https://%s/login' %avi_controller, verify=False, data={'username': avi_user, 'password': avi_pass})


def avi_request(avi_api,tenant):
    cookies=dict()
    if 'avi-sessionid' in login.cookies.keys():
        cookies['avi-sessionid'] = login.cookies['avi-sessionid']
    else:
        cookies['sessionid'] = login.cookies['sessionid']
    headers = ({"X-Avi-Tenant": "%s" %tenant, 'content-type': 'application/json','X-Avi-Version': '%s' %api_version})
    return requests.get('https://%s/api/%s' %(avi_controller,avi_api), verify=False, headers = headers,cookies=cookies)


def avi_post(api_url,tenant,payload):
    cookies=dict()
    if 'avi-sessionid' in login.cookies.keys():
        cookies['avi-sessionid'] = login.cookies['avi-sessionid']
    else:
        cookies['sessionid'] = login.cookies['sessionid']      
    headers = ({"X-Avi-Tenant": "%s" %tenant, 'content-type': 'application/json','referer': 'https://%s' %avi_controller, 'X-CSRFToken': dict(login.cookies)['csrftoken'],'X-Avi-Version':'%s' %api_version})
    cookies['csrftoken'] = login.cookies['csrftoken']
    return requests.post('https://%s/api/%s' %(avi_controller,api_url), verify=False, headers = headers,cookies=cookies, data=json.dumps(payload),timeout=600)


def avi_delete(api_url,tenant):
    headers = ({"X-Avi-Tenant": "%s" %tenant, 'content-type': 'application/json','X-Avi-Version': '%s' %api_version,'referer': 'https://%s' %avi_controller, 'X-CSRFToken': dict(login.cookies)['csrftoken']})
    cookies = dict(sessionid= login.cookies['sessionid'],csrftoken=login.cookies['csrftoken'])
    return requests.delete('https://%s/api/%s' %(avi_controller,api_url), verify=False, headers = headers,cookies=cookies)


def avi_put(api_url,tenant,payload):
    headers = ({"X-Avi-Tenant": "%s" %tenant, 'content-type': 'application/json','X-Avi-Version': '%s' %api_version,'referer': 'https://%s' %avi_controller, 'X-CSRFToken': dict(login.cookies)['csrftoken']})
    cookies = dict(sessionid= login.cookies['sessionid'],csrftoken=login.cookies['csrftoken'])
    return requests.put('https://%s/api/%s' %(avi_controller,api_url), verify=False, headers = headers,cookies=cookies, data=json.dumps(payload))



#--------------------------------




def import_configuration_yaml():
    if 'EN_CONFIGURATION' in os.environ:
        try:
            configuration = yaml.safe_load(os.environ['EN_CONFIGURATION'].replace('\t','  '))
            #print(configuration)
            #dir = '/var/avi/'
            #with open(fdir+os.environ['deployment'], 'r') as yaml_file:
            #    configuration = yaml.safe_load(yaml_file)
            #yaml_file.close()
            configuration = set_configuration_defaults(configuration)
            return configuration          
        except:
            logging.error(str(datetime.now())+' Error with Provided Configuration YAML')
            exception_text = traceback.format_exc()
            logging.error(str(datetime.now())+' : '+exception_text)
            sys.exit(1)
    else:
        logging.error(str(datetime.now())+' No configuration file referenced')
        sys.exit(1)



def set_configuration_defaults(configuration):
    if configuration.get('datacenter') == None:
        configuration['datacenter'] = 'SDDC-Datacenter'
    if configuration.get('datastore') == None:
        configuration['datastore'] = 'WorkloadDatastore'
    if configuration.get('cluster') == None:
        configuration['cluster'] = 'Cluster-1'
    if configuration.get('folder') == None:
        configuration['folder'] = '/SDDC-Datacenter/vm'
    else:
        if configuration['folder'].startswith('/') == False:
            configuration['folder'] = '/'+configuration['folder']
    if configuration.get('resourcepool') == None:
        configuration['resourcepool'] = ''    
    if configuration.get('tenant') == None:
        configuration['tenant'] = 'admin'            
    if configuration.get('cloud') == None:
        configuration['cloud'] = 'Default-Cloud'
    if configuration.get('segroup') == None:
        configuration['segroup'] = 'Default-Group'
    if configuration.get('ctl_memory_mb') == None:
        configuration['ctl_memory_mb'] = '24576'
    if configuration.get('ctl_num_cpus') == None:
        configuration['ctl_num_cpus'] = '8'
    if configuration.get('ctl_disk_size_gb') == None:
        configuration['ctl_disk_size_gb'] = '128'
    if configuration.get('se_memory_mb') == None:
        configuration['se_memory_mb'] = '2048'
    if configuration.get('se_num_cpus') == None:
        configuration['se_num_cpus'] = '1'
    if configuration.get('se_disk_size_gb') == None:
        configuration['se_disk_size_gb'] = '20'     
    if configuration.get('data_nic_parking_pg') == None:   
        configuration['data_nic_parking_pg'] = configuration['management_network_pg']
    if configuration.get('three_node_cluster') == None:
        configuration['three_node_cluster'] = False
    if configuration.get('number_to_deploy') == None:
        configuration['number_to_deploy'] = 1        
    if 'node1_mgmt_ip' in configuration:
        os.chdir('/usr/src/avideploy/')
        for ovafile in glob.glob('controller*.ova'):
            configuration['ova_path'] = '/usr/src/avideploy/'+ovafile
    return configuration






def create_ssh_key():
    global avi_ssh_key
    result = os.system('ssh-keygen -b 4096 -t rsa -f /tmp/avi_id_ssh_rsa -q -N ""')
    if result == 0:
        logging.info(str(datetime.now())+' Temp SSH key generated')
        f = open('/tmp/avi_id_ssh_rsa.pub','r')
        avi_ssh_key = f.read().strip()
        f.close()
        #avi_ssh_key = '/tmp/avi_id_ssh_rsa.pub'
    else:
        logging.error(str(datetime.now())+' Temp SSH key generation failed')
        sys.exit(1)




def generate_govc_variables(configuration):
    global govc_vars
    govc_vars = ("export GOVC_DATACENTER=%s; "
                 "export GOVC_DATASTORE=%s; "
                 "export GOVC_URL='%s:%s@%s'; "
                 "export GOVC_INSECURE=true;" %(configuration['datacenter'],configuration['datastore'],configuration['vcenter_username'],configuration['vcenter_password'],configuration['vcenter_hostname']))

    


def create_content_library_item(entity_type):
    if entity_type == 'controller':
        lib_items = os.popen(govc_vars+'./govc library.info avi/').read().split('\n')
        if len(lib_items) == 0:
            #logging.info(str(datetime.now())+' Create Content Library avi')
            print(str(datetime.now())+' Create Content Library avi')
            os.popen(govc_vars+'./govc library.create  avi').read()
        elif os.popen(govc_vars+'./govc library.ls  avi/'+configuration['ova_path'].rsplit('/',1)[1].split('.ova')[0]).read() == '':
            #logging.info(str(datetime.now())+' Uploading controller ova to Content Library avi')
            print(str(datetime.now())+' Uploading controller ova to Content Library avi')
            os.popen(govc_vars+'./govc library.import  avi '+configuration['ova_path']).read()
        else:
            print(str(datetime.now())+' controller ova already exists in content library avi')
            #logging.info(str(datetime.now())+' controller ova already exists in content library avi')
    elif entity_type == 'se':
        lib_items = os.popen(govc_vars+'./govc library.info avi/').read().split('\n')
        if len(lib_items) == 0:
            #logging.info(str(datetime.now())+' Create Content Library avi')
            print(str(datetime.now())+' Create Content Library avi')
            os.popen(govc_vars+'./govc library.create  avi').read()
        elif os.popen(govc_vars+'./govc library.ls  avi/'+configuration['ova_path'].rsplit('/',1)[1].split('.ova')[0]).read() == '':
            print(str(datetime.now())+' Uploading se ova to Content Library avi')
            os.popen(govc_vars+'./govc library.import  avi '+configuration['ova_path']).read()
        else:
            print(str(datetime.now())+' se ova already exists in content library avi')




#----- this doesn't fucking work
def controller_generate_spec(configuration,controller_number):
    controller_number = str(controller_number)
    #spec = controller_spec_template.copy()
    spec = copy.deepcopy(controller_spec_template)
    if configuration.get('node'+controller_number+'_mgmt_ip') != None:
        for e in spec['PropertyMapping']:
           if e['Key'] == 'avi.mgmt-ip.CONTROLLER':
               e['Value'] = configuration['node'+controller_number+'_mgmt_ip']
           elif e['Key'] == 'avi.mgmt-mask.CONTROLLER':
               if '.' in str(configuration['node'+controller_number+'_mgmt_mask']):
                   e['Value'] = str((IPNetwork('0.0.0.0/'+(str(configuration['node'+controller_number+'_mgmt_mask']))).prefixlen))
               else:
                   e['Value'] = str(configuration['node'+controller_number+'_mgmt_mask'])
           elif e['Key'] == 'avi.default-gw.CONTROLLER':
               e['Value'] = configuration['node'+controller_number+'_mgmt_gw']
    for e in spec['PropertyMapping']:
        if e['Key'] == 'avi.sysadmin-public-key.CONTROLLER':
            e['Value'] = avi_ssh_key          
    spec['NetworkMapping'][0]['Network'] = configuration['management_network_pg']
    spec['Name'] = 'controller'+controller_number
    return spec
        
            


def check_portal_status(avi_controller):
    class portal_status:pass
    portal_status.status_code = None
    #-------
    while portal_status.status_code != 200:
        print(str(datetime.now())+' Waiting for controller-'+avi_controller+' API to be Available')
        try:
            portal_status = requests.get('https://'+avi_controller+'/api/initial-data',verify=False, timeout=5)
            time.sleep(60)
        except:
            time.sleep(60)
    portal_status.status_code = None
    while portal_status.status_code != 401:
        portal_status = requests.post('https://'+avi_controller+'/login',verify=False, timeout=5)
        time.sleep(60)




def deploy_controller(configuration):
    create_content_library_item('controller')
    controller_number = 1
    global controller_list
    controller_list = []
    if configuration['three_node_cluster'] == True:
        num_of_controllers = 3
    else:
        num_of_controllers = 1
    while controller_number <= num_of_controllers:
        controller_spec = controller_generate_spec(configuration,controller_number)
        with open('properties.json', 'w') as f:
          json.dump(controller_spec, f)
        f.close()
        print(str(datetime.now())+' Deploying controller'+str(controller_number))
        os.popen(govc_vars+'./govc library.deploy -folder='+configuration['folder'].rsplit('/',1)[1]+' -pool='+configuration['resourcepool']+' -options=./properties.json /avi/'+configuration['ova_path'].rsplit('/',1)[1].split('.ova')[0]+' controller'+str(controller_number)).read()
        if configuration['ctl_num_cpus'] != None:
            print(str(datetime.now())+' Setting controller'+str(controller_number)+' cpu')
            os.popen(govc_vars+'./govc vm.change -vm controller'+str(controller_number)+' -c '+configuration['ctl_num_cpus'])
        if configuration['ctl_memory_mb'] != None:
            print(str(datetime.now())+' Setting controller'+str(controller_number)+' memory')
            os.popen(govc_vars+'./govc vm.change -vm controller'+str(controller_number)+' -m '+configuration['ctl_memory_mb'])
        if configuration['ctl_disk_size_gb'] != None:
            print(str(datetime.now())+' Setting controller'+str(controller_number)+' disk')
            os.popen(govc_vars+'./govc vm.disk.change -vm controller'+str(controller_number)+' -size '+configuration['ctl_disk_size_gb']+'G')
        time.sleep(15)
        print(str(datetime.now())+' Powering on controller'+str(controller_number))        
        os.popen(govc_vars+'./govc vm.power -on controller'+str(controller_number)).read()
        controller_ip = os.popen(govc_vars+'./govc vm.ip controller'+str(controller_number)).read()
        controller_list.append(controller_ip.strip())
        print(str(datetime.now())+' Rename controller'+str(controller_number)+' ==> controller-'+controller_ip)
        os.popen(govc_vars+'./govc vm.change -vm controller'+str(controller_number)+' -name=controller-'+controller_ip).read()
        if controller_number == 1:
            global avi_controller
            avi_controller = controller_ip.strip()
        controller_number += 1
    check_portal_status(avi_controller)
    print(str(datetime.now())+' Adding controller-'+avi_controller+' to known_hosts')
    os.system("ssh -o 'StrictHostKeyChecking no' -i /tmp/avi_id_ssh_rsa admin@"+avi_controller+" cat /etc/ssh/ssh_host_ecdsa_key.pub >>~/.ssh/known_hosts")
    time.sleep(10)
    print(str(datetime.now())+' Setting controller-'+avi_controller+' admin password')
    #os.popen("ssh -o 'StrictHostKeyChecking no' -i /tmp/avi_id_ssh_rsa admin@"+avi_controller+" cat /etc/ssh/ssh_host_ecdsa_key.pub >>~/.ssh/known_hosts")
    os.system("ssh -i /tmp/avi_id_ssh_rsa admin@"+avi_controller+" sudo /opt/avi/scripts/initialize_admin_user.py --password "+configuration['avi_admin_password'])
    time.sleep(15)
    print(str(datetime.now())+' Cleaning up temp ssh keys')
    os.system('rm -f /tmp/avi_id_ssh_rsa*')
    print(str(datetime.now())+' Cleaning up temp files')
    os.system('rm -f ./properties.json')



def configure_controller_defaults_vmc(configuration):
    #----- systemconfiguration: workflow complete
    print(str(datetime.now())+' Modify welcome_workflow_complete')    
    resp = avi_request('systemconfiguration', 'admin').json()
    resp['welcome_workflow_complete'] = True
    resp = avi_put('systemconfiguration', 'admin', resp)
    #----- modify cloud
    print(str(datetime.now())+' Modify cloud '+configuration['cloud'])
    resp = avi_request('cloud?name='+configuration['cloud'], 'admin').json()['results'][0]
    cloud_uuid = resp['uuid']
    resp['vmc_deployment'] = True
    avi_put('cloud/'+cloud_uuid,'admin', resp)


    
def authenticate_to_avi(configuration):
    print(str(datetime.now())+' Authenticating to Avi Controller')
    if configuration.get('avi_username') == None:
        avi_login('admin',configuration['avi_admin_password'])
    else:
        global avi_controller
        avi_controller = configuration['avi_controller_ip']
        avi_login(configuration['avi_username'],configuration['avi_password'])
    global api_version
    api_version = login.json()['version']['Version']
    

        
def generate_se_ova(configuration):
    print(str(datetime.now())+' Generating SE OVA')
    #if configuration.get('cluster_vip') != None and configuration['three_node_cluster'] == True:
    #    c_ip = configuration['cluster_vip']
    #else:
    #    c_ip = avi_controller
    cluster_uuid = avi_request('cluster','admin').json()['uuid']
    resp = avi_post('fileservice/seova','admin', {'file_format': 'ova'})
    if resp.status_code == 201:
        print(str(datetime.now())+' Uploading SE to content library')
        se_path = '/host/pkgs/'+login.json()['version']['Tag']+'/se.ova'
        print(str(datetime.now())+' Download SE from controller')
        os.system('sshpass -p '+configuration['avi_admin_password']+' scp -r admin@'+avi_controller+':'+se_path+' ./se-'+cluster_uuid+'.ova')
        print(str(datetime.now())+' Uploading SE to content library')
        os.popen(govc_vars+'./govc library.import  avi ./se-'+cluster_uuid+'.ova').read()
        time.sleep(15)
        print(str(datetime.now())+' Cleaning up local se file: se.ova')
        os.system('rm -f ./se-'+cluster_uuid+'.ova')





def configure_cluster(configuration):
    print(str(datetime.now())+' Creating 3-Node Cluster')
    cluster_payload = {}
    cluster_payload['nodes'] = []
    for i in controller_list:
        cluster_payload['nodes'].append({'ip':{'type':'V4','addr':i},'name':'controller-'+i})
    if configuration.get('cluster_vip') != None:
        cluster_payload['virtual_ip'] = {'type': 'V4', 'addr': configuration['cluster_vip']}
    resp = avi_put('cluster','admin',cluster_payload)
    if resp.status_code == 200:
        if configuration.get('cluster_vip') != None:
            check_portal_status(configuration['cluster_vip'])
        else:
            time.sleep(300)
            check_portal_status(controller_list[0])
    else:
        print(str(datetime.now())+' Failed to create 3-Node Cluster')
        print(resp)



    
def check_for_se_ova(configuration):
    print(str(datetime.now())+' Checking for SE ova in content library')
    resp = os.popen(govc_vars+' ./govc library.ls /avi/*').read().split()
    if len(resp) > 0:
        for r in resp:
            if r.split('/avi/',1)[1] == 'se-'+cluster_uuid:
                print(str(datetime.now())+' SE ova already exists in content library')
                return True                    
    generate_se_ova(configuration)
        


def se_generate_spec(configuration,auth_token):
    #spec = controller_spec_template.copy()
    spec = copy.deepcopy(se_spec_template)
    if configuration.get('se_mgmt_ip') != None:
        for e in spec['PropertyMapping']:
            if e['Key'] == 'avi.mgmt-ip.SE':
                e['Value'] = configuration['se_mgmt_ip']
            elif e['Key'] == 'avi.mgmt-mask.SE':
                if '.' in str(configuration['se_mgmt_mask']):
                    e['Value'] = str((IPNetwork('0.0.0.0/'+(str(configuration['se_mgmt_mask']))).prefixlen))
                else:
                    e['Value'] = str(configuration['se_mgmt_mask'])
            elif e['Key'] == 'avi.default-gw.SE':
                e['Value'] = configuration['se_mgmt_gw']
    for e in spec['PropertyMapping']:
        if e['Key'] == 'AVICNTRL':
            e['Value'] = avi_controller
        elif e['Key'] == 'AVICNTRL_AUTHTOKEN':
            e['Value'] = auth_token
    spec['NetworkMapping'][0]['Network'] = configuration['management_network_pg']
    #------ Set SE Data Nic Portgoups
    data_pg = {}
    for n in range(1,10):
        if configuration.get('data_network'+str(n)).get('se_int_pg') != None:
            data_pg['Data Network '+str(n)] = configuration['data_network'+str(n)]['se_int_pg']
        else:
            data_pg['Data Network '+str(n)] = configuration['data_nic_parking_pg']
    for d in spec['NetworkMapping']:
        if d['Name'] in data_pg:
            d['Network'] = data_pg[d['Name']]
    return spec






def get_se_authtoken(configuration):
    print(str(datetime.now())+' Generating SE auth token')
    cloud_uuid = avi_request('cloud?name='+configuration['cloud'],configuration['tenant']).json()['results'][0]['uuid']
    se_auth_token = avi_request('securetoken-generate?cloud_uuid='+cloud_uuid, configuration['tenant'])
    if se_auth_token.status_code == 200:
        return se_auth_token.json()['auth_token']
    else:
        print(str(datetime.now())+' Failed to generate SE auth token')
        sys.exit()




def check_se_status():
    print(str(datetime.now())+' Waiting for SE to be seen by Controller')
    resp = avi_request('serviceengine?name='+se_ip,configuration['tenant']).json()
    while resp['count'] == 0:
        time.sleep(30)
        print(str(datetime.now())+' Waiting for SE to be seen by Controller')
        resp = avi_request('serviceengine?name='+se_ip,configuration['tenant']).json()
    #-------
    print(str(datetime.now())+' Waiting for SE to connect to Controller')
    resp = avi_request('serviceengine?name='+se_ip,configuration['tenant']).json()['results'][0]
    while resp['se_connected'] != True:
        time.sleep(30)
        print(str(datetime.now())+' Waiting for SE to connect to Controller')
        resp = avi_request('serviceengine?name='+se_ip,configuration['tenant']).json()['results'][0]
    time.sleep(15)





def deploy_se(configuration):
    check_for_se_ova(configuration)
    se_auth_token = get_se_authtoken(configuration)
    se_spec = se_generate_spec(configuration,se_auth_token)
    with open('properties.json', 'w') as f:
      json.dump(se_spec, f)
    f.close()
    print(str(datetime.now())+' Deploying SE')
    os.popen(govc_vars+'./govc library.deploy -folder='+configuration['folder'].rsplit('/',1)[1]+' -pool='+configuration['resourcepool']+' -options=./properties.json /avi/se-'+cluster_uuid+' avise').read()
    if configuration['se_num_cpus'] != None:
        print(str(datetime.now())+' Setting se cpu')
        os.popen(govc_vars+'./govc vm.change -vm avise -c '+str(configuration['se_num_cpus']))
    if configuration['se_memory_mb'] != None:
        print(str(datetime.now())+' Setting avise memory')
        os.popen(govc_vars+'./govc vm.change -vm avise -m '+str(configuration['se_memory_mb']))
    if configuration['se_disk_size_gb'] != None:
        print(str(datetime.now())+' Setting avise disk')
        os.popen(govc_vars+'./govc vm.disk.change -vm avise -size '+str(configuration['se_disk_size_gb'])+'G')
    print(str(datetime.now())+' Powering on avise')
    time.sleep(15)
    os.popen(govc_vars+'./govc vm.power -on avise').read()
    global se_ip
    se_ip = os.popen(govc_vars+'./govc vm.ip avise').read().strip()
    print(str(datetime.now())+' Rename avise ==> avise-'+se_ip)
    os.popen(govc_vars+'./govc vm.change -vm avise -name=avise-'+se_ip).read()
    check_se_status()




def configure_se_data_segroup(configuration):
    #----- map VM INT to Mac address {data_network : macaddress}
    print(str(datetime.now())+' Configuring avise-'+se_ip+' data interfaces and segroup') 
    vm_int_macs = {}
    vm = (json.loads(os.popen(govc_vars+'./govc ls -json '+configuration['folder']+'/avise-'+se_ip).read()))
    vm = vm['elements'][0]['Object']['Config']['Hardware']['Device']
    for d in vm:
        if 'Network adapter ' in d['DeviceInfo']['Label']:
            device_id = 'data_network'+(str(int(d['DeviceInfo']['Label'].rsplit(' ',1)[1])-1))
            vm_int_macs[device_id] = d['MacAddress']
    #----- Map mac address to se int {macaddress : seint}
    se_int_macs = {}
    se = avi_request('serviceengine?name='+se_ip,configuration['tenant']).json()['results'][0]
    for n in se['data_vnics']:
        se_int_macs[n['mac_address']] = n['linux_name']
    #----- map VM int to SE INT {data_networkX : seint}
    int_map = {}
    for v in vm_int_macs:
        if vm_int_macs[v] in se_int_macs:
            int_map[v] = se_int_macs[vm_int_macs[v]]
    #----- Configure SE Interfaces: Static IP Addresses or DHCP
    for n in range(1,10):
        if configuration.get('data_network'+str(n)).get('se_int_pg') != None:
            #----- STATIC IPs
            if configuration.get('data_network'+str(n)).get('se_int_ip') != None:
                if '.' in str(configuration['data_network'+str(n)]['se_int_mask']):
                   ip_mask = int(IPNetwork('0.0.0.0/'+str(configuration['data_network'+str(n)]['se_int_mask'])).prefixlen)
                else:
                    ip_mask = int(configuration['data_network'+str(n)]['se_int_mask'])
                _int = int_map['data_network'+str(n)]
                _p = [
                    {
                        'ip':{
                            'ip_addr': {
                                'addr': configuration['data_network'+str(n)]['se_int_ip'],
                                'type': 'V4'
                            },
                            'mask': ip_mask
                        },
                        'mode': 'STATIC'
                    }
                ]
                for v in se['data_vnics']:
                    if v['linux_name'] == _int:
                        v['vnic_networks'] = _p
            #----- DHCP                                    
            else:
                _int = int_map['data_network'+str(n)]
                for v in se['data_vnics']:
                    if v['linux_name'] == _int:
                        v['dhcp_enabled'] = True
    #----- Modify SE Group                        
    if configuration['segroup'] != 'Default-Group':
        segroup_url = avi_request('serviceenginegroup?name='+configuration['segroup']+'&cloud_ref.name='+configuration['cloud'],configuration['tenant'])
        segroup_url = segroup_url.json()['results'][0]['url']
        se['se_group_ref'] = segroup_url
    #----- Post config
    resp = avi_put('serviceengine/'+se['uuid'],configuration['tenant'],se)
    if resp.status_code == 200:
        print(str(datetime.now())+' Configuring avise-'+se_ip+' data interfaces and segroup successful')
    else:
        print(str(datetime.now())+' Error configuring avise-'+se_ip+' data interfaces and segroup')
        print(resp, resp.text)
    if configuration['segroup'] != 'Default-Group':
        time.sleep(15)
        print(str(datetime.now())+' Segroup for avise-'+se_ip+' changed')
        check_se_status()

  

def connect_disconnect_unused_vnics(configuration):
    for n in range(1,10):
        if configuration.get('data_network'+str(n)).get('se_int_pg') != None:
            print(str(datetime.now())+' Connecting used data interface for avise-'+se_ip)
            os.popen(govc_vars+'./govc device.connect -vm=avise-'+se_ip+' ethernet-'+str(n)).read()
        elif configuration.get('data_network'+str(n)).get('se_int_pg') == None:
            print(str(datetime.now())+' Disconnecting unused data interface for avise-'+se_ip)
            os.popen(govc_vars+'./govc device.disconnect -vm=avise-'+se_ip+' ethernet-'+str(n)).read()

                

    
    


def controller_check_config_requirements(configuration):
    if configuration.get('vcenter_hostname') == None:
        print(str(datetime.now())+' Configuration file missing required value: vcenter_hostname')
        sys.exit()
    elif configuration.get('vcenter_username') == None:
        print(str(datetime.now())+' Configuration file missing required value: vcenter_username')
        sys.exit()  
    elif configuration.get('vcenter_password') == None:
        print(str(datetime.now())+' Configuration file missing required value: vcenter_password')
        sys.exit()        
    elif configuration.get('management_network_pg') == None:
        print(str(datetime.now())+' Configuration file missing required value: management_network_pg')
        sys.exit()
    elif configuration.get('avi_admin_password') == None:
        print(str(datetime.now())+' Configuration file missing required value: avi_admin_password')
        sys.exit()     
    else:
        return True             




def se_check_config_requirements(configuration):
    if configuration.get('vcenter_hostname') == None:
        print(str(datetime.now())+' Configuration file missing required value: vcenter_hostname')
        sys.exit()
    elif configuration.get('vcenter_username') == None:
        print(str(datetime.now())+' Configuration file missing required value: vcenter_username')
        sys.exit()  
    elif configuration.get('vcenter_password') == None:
        print(str(datetime.now())+' Configuration file missing required value: vcenter_password')
        sys.exit()        
    elif configuration.get('avi_controller_ip') == None:
        print(str(datetime.now())+' Configuration file missing required value: avi_controller_ip')
        sys.exit()     
    elif configuration.get('avi_username') == None:
        print(str(datetime.now())+' Configuration file missing required value: avi_username')
        sys.exit()     
    elif configuration.get('avi_password') == None:
        print(str(datetime.now())+'Configuration file missing required value: avi_password')
        sys.exit()    
    elif configuration.get('management_network_pg') == None:
        print(str(datetime.now())+' Configuration file missing required value: management_network_pg')
        sys.exit()
    else:
        return True      






    



if __name__ == '__main__':
    try:
        configuration = import_configuration_yaml()
        if 'node1_mgmt_ip' in configuration:
            controller_check_config_requirements(configuration)
            generate_govc_variables(configuration)
            create_ssh_key()
            deploy_controller(configuration)
            authenticate_to_avi(configuration)
            configure_controller_defaults_vmc(configuration)
            if configuration['three_node_cluster'] == True:
                configure_cluster(configuration)
            generate_se_ova(configuration)
        elif 'se_mgmt_ip' in configuration:
            run_number = 0
            while run_number < configuration['number_to_deploy']:
                se_check_config_requirements(configuration)
                generate_govc_variables(configuration)
                authenticate_to_avi(configuration)
                cluster_uuid = avi_request('cluster','admin').json()['uuid']
                print(str(datetime.now())+' Deploying SE '+str(run_number+1)+'/'+str(configuration['number_to_deploy']))
                deploy_se(configuration)
                configure_se_data_segroup(configuration)
                connect_disconnect_unused_vnics(configuration)
                run_number += 1
    except:
        exception_text = traceback.format_exc()
        print(str(datetime.now())+'  : '+exception_text)
        sys.exit(1)
    sys.exit(0)



#----------------- DELETE ALL BELOW THIS LINE ----------------------


#with open('./delete.yml', 'r') as yaml_file:
#            configuration = yaml.safe_load(yaml_file)
#            yaml_file.close()
#            configuration = set_configuration_defaults(configuration)



#def main():
#    generate_govc_variables(configuration)
#    if 'node1_mgmt_ip' in configuration:  
#        create_ssh_key()  
#        deploy_controller(configuration)
#        authenticate_to_avi(configuration)
#        configure_controller_defaults_vmc(configuration)
#        if configuration['three_node_cluster'] == True:
#            configure_cluster(configuration)
#        generate_se_ova(configuration)
#    elif 'se_mgmt_ip' in configuration:
#            generate_govc_variables(configuration)
#            authenticate_to_avi(configuration)
#            deploy_se(configuration)
#            configure_se_data_segroup(configuration)
#            connect_disconnect_unused_vnics(configuration)  


