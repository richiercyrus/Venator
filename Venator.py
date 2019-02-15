import os
import datetime
import logging
import math
import sys
import plistlib
import string
import struct
import xml.parsers.expat
import subprocess
import json
import socket
import Foundation
import Quartz
import argparse


#get the hostname of the system the script is running on
hostname = socket.gethostname()


def getSystemInfo(output_file):
    system_data = {}
    uname = os.uname()
    system_data.update({'hostname':uname[1]})
    system_data.update({'kernel':uname[2]})
    system_data.update({'kernel_release':uname[3].split(';')[1].split(':')[1]})
    system_data.update({"module":"System Info"})
    json.dump(system_data,output_file)
    outfile.write("\n")

def getHash(file):
    import hashlib
    hasher = hashlib.sha256()
    with open(file, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return(hasher.hexdigest())

def datetime_handler(x):
    if isinstance(x, datetime.datetime):
        return x.isoformat()
    #raise TypeError("Unknown type")

def getLaunchAgents(path,output_file):
    #get all of the launch agents at a specififc location returned into a list
    systemAgents = os.listdir(path)

    #for each of the launchAgents, parse the contents into a dictionary, add the name of the plist and the location to the dictionary
    for agent in systemAgents:
      parsedAgent = {}
      plist_file = path+"/"+agent
      plist_type = subprocess.Popen(["file", plist_file], stdout=subprocess.PIPE).communicate()
      plist_type = plist_type[0].split(":")[1].strip("\n").strip(" ")
      #if else the file is a binary plist, then we have to use the Foundations framework to read the plist cleanly
      if plist_type == 'Apple binary property list':
        plist = Foundation.NSDictionary.dictionaryWithContentsOfFile_(plist_file)
      elif plist_type == 'XML 1.0 document text, ASCII text':
        plist = plistlib.readPlist(plist_file)
      elif plist_type == 'exported SGML document text, ASCII text':
        plist_text = subprocess.Popen(["cat", plist_file], stdout=subprocess.PIPE).communicate()
        #plist_text = plist_text[0].split("\n")
        if plist_text[0].split("\n")[0].startswith("<?xml"):
          #plist = plistlib.readPlist(plist_file)
          plistlib.readPlistFromString(plist_text)
        else:
          xml_start = plist_text[0].find('<?xml')
          plist_string = plist_text[0][xml_start:]
          #del plist_text[0]
          #str1 = '\n'.join(plist_text)
          plist = plistlib.readPlistFromString(plist_string)
      parsedAgent.update({'Label': str(plist.get("Label"))})
      parsedAgent.update({'Program': str(plist.get("Program"))})
      parsedAgent.update({'Program Arguments': str(plist.get("ProgramArguments"))})
      parsedAgent.update({'Run At Load': str(plist.get("RunAtLoad"))})
      parsedAgent.update({'hash': getHash(plist_file)})
      parsedAgent.update({'Path': plist_file})
      parsedAgent.update({"module":"Launch Agents"})
      parsedAgent.update({"Hostname":hostname})
      json.dump(parsedAgent,output_file)
      outfile.write("\n")

def getLaunchDaemons(path,output_file):

    systemDaemons = os.listdir(path)
    #parsedDaemon = {}
    #for each of the launchAgents, parse the contents into a dictionary, add the name of the plist and the location to the dictionary
    for daemon in systemDaemons:
      parsedDaemon = {}
      plist_file = path+"/"+daemon
      plist_type = subprocess.Popen(["file", plist_file], stdout=subprocess.PIPE).communicate()
      plist_type = plist_type[0].split(":")[1].strip("\n").strip(" ")
      #if else the file is a binary plist, then we have to use external library to parse
      if plist_type == 'Apple binary property list':
        plist = Foundation.NSDictionary.dictionaryWithContentsOfFile_(plist_file)
      elif plist_type == 'XML 1.0 document text, ASCII text':
        plist = plistlib.readPlist(plist_file)
      parsedDaemon.update({'Label': str(plist.get("Label"))})
      parsedDaemon.update({'Program': str(plist.get("Program"))})
      parsedDaemon.update({'Program Arguments': str(plist.get("ProgramArguments"))})
      parsedDaemon.update({'hash': getHash(plist_file)})
      parsedDaemon.update({'Path': plist_file})
      parsedDaemon.update({"module":"Launch Daemons"})
      parsedDaemon.update({"Hostname":hostname})
      json.dump(parsedDaemon,output_file)
      outfile.write("\n") 

def getUsers(output_file):
    users_dict = {}
    all_users = []
    #run command to get a list of all the users
    users = subprocess.Popen(["dscl",".","list","/Users"], stdout=subprocess.PIPE).communicate()
    users = users[0].split("\n")
    #if the user is a normal system account, add to the all users array/list
    for user in users:
        if user.startswith('_') == False:
             all_users.append(user)
    users_dict.update({'users': all_users})
    users_dict.update({"module":"Users"})
    users_dict.update({"Hostname":hostname})
    json.dump(users_dict,output_file)
    outfile.write("\n")
    return users_dict

def getSafariExtensions(path,output_file):
  #safariExtensions = {}
  extension = []
  plist_file = path+'/Extensions.plist'
  plist = Foundation.NSDictionary.dictionaryWithContentsOfFile_(plist_file)
  for ext in plist.get("Installed Extensions"):
    safariExtensions = {}
    safariExtensions.update({"module":"Safari Extensions"})  
    safariExtensions.update({'Extension Name':ext.get("Archive File Name")})
    safariExtensions.update({'Apple Signed':ext.get("Apple-signed")})
    safariExtensions.update({'Developer Identifier':ext.get("Developer Identifier")})
    safariExtensions.update({'Extensions Path':plist_file})
    safariExtensions.update({"Hostname":hostname})
    json.dump(safariExtensions,output_file)
    outfile.write("\n")

def getChromeExtensions(path,output_file):
  extensions_directories = os.listdir(path)
  for directory in extensions_directories:
    full_path = path+directory
    for root, dirs, files in os.walk(full_path, topdown=False):
     for name in files:
       if name == "manifest.json":
         with open(os.path.join(root,name),'r') as manifest:
           manifest_dump = manifest.read()
         manifest_json = json.loads(manifest_dump)
         for field in manifest_json:
           extensions = {}
           if field == "name":
             if manifest_json.get("name").startswith('__') == False:
               extensions.update({"Extension Directory Name":directory})
               extensions.update({"Extension Update Url":manifest_json.get("update_url").strip('u\'')})
               extensions.update({"Extension Name":manifest_json.get("name").strip('u\'')})
               extensions.update({"module":"Chrome Extensions"})
               extensions.update({"Hostname":hostname})
               json.dump(extensions,output_file)
               outfile.write("\n")

def getFirefoxExtensions(path,output_file):
  with open(path+"profiles.ini",'r') as profile_data:
    profile_dump = profile_data.read()
  
  extensions_path = profile_dump[profile_dump.find("Path="):profile_dump.find(".default")+8]
      
  extensions_path = extensions_path.split("=")[1]

  with open(path+extensions_path+"/extensions.json", 'r') as extensions:
    extensions_dump = extensions.read()
  extensions_json = json.loads(extensions_dump)

  for field in extensions_json.get("addons"):
    firefox_extensions = {}
    firefox_extensions.update({"Extension ID": field.get("id")})
    firefox_extensions.update({"Extension Update URL": field.get("updateURL")})
    firefox_extensions.update({"Extension Options URL": field.get("optionsURL")})
    firefox_extensions.update({"Extension Install Date": field.get("installDate")})
    firefox_extensions.update({"Extension Last Updated": field.get("updateDate")})
    firefox_extensions.update({"Extension Source URI": field.get("sourceURI")})
    firefox_extensions.update({"Extension Name": field.get("defaultLocale").get("name")})
    firefox_extensions.update({"Extension Description": field.get("defaultLocale").get("description")})    
    firefox_extensions.update({"Extension Creator": field.get("defaultLocale").get("creator")})
    firefox_extensions.update({"Extension Homepage URL": field.get("defaultLocale").get("homepageURL")})
    firefox_extensions.update({"module":"Firefox Extensions"})
    firefox_extensions.update({"Hostname":hostname})        
    json.dump(firefox_extensions,output_file)
    outfile.write("\n")

def getTmpFiles():
  temporaryFiles = {}
  tempFiles = {}
  for root, dirs, files in os.walk('/tmp', topdown=False):
    for name in files:
      tmp = (os.path.join(root, name))
      try:
        tempFiles.update({tmp:getHash(tmp)})
      except:
        ""
  temporaryFiles.update({'tmpFiles':tempFiles})
  temporaryFiles.update({"Hostname":hostname})
  return temporaryFiles

def getDownloads():
  downloadedFiles = {}
  downloads = {}
  for root, dirs, files in os.walk('/Users/casper/Downloads', topdown=False):
    for name in files:
      dwn_load = (os.path.join(root, name))
      try:
        downloads.update({dwn_load:getHash(dwn_load)})
      except:
        ""
  downloadedFiles.update({'tmpFiles':downloads})
  downloadedFiles.update({"Hostname":hostname})
  return downloadedFiles

def getInstallHistory(output_file):
  path = '/Library/Receipts/InstallHistory.plist'
  history = plistlib.readPlist(path)
  for item in history:
    tempdict = item
    installList = {}
    installList.update({"date":tempdict.get('date')})
    installList.update({"displayName":tempdict.get('displayName')})
    installList.update({"packageIdentifiers":tempdict.get('packageIdentifiers')})
    installList.update({"module":"Install History"})
    installList.update({"Hostname":hostname})
    json.dump(installList,output_file,default=datetime_handler,encoding='latin1')
    output_file.write("\n")
    

def getCronJobs(users,output_file):
  #get all of the current users
  usercrons = {}
  for user in users:
    #results in a tuple
    users_crontab = subprocess.Popen(["crontab","-u",user,"-l"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()
    #add user and associated crontabs to dict usercrons
    usercrons.update({user:users_crontab})
    usercrons.update({"module":"Cron Jobs"})
    usercrons.update({"Hostname":hostname})
    json.dump(usercrons,output_file)
    output_file.write("\n")
  #cronJobs.update({"cronJobs":usercrons})
  #return cronJobs

def getEmond(output_file):
  emondRules = []
  Emond = {}
  allRules = {}
  for root, dirs, files in os.walk('/etc/emond.d/rules/', topdown=False):
    for name in files:
      emondRules.append(os.path.join(root, name))
  for rule in emondRules:
    allRules.update({rule:plistlib.readPlist(rule)})
    allRules.update({"module":"Emond Rules"})
    allRules.update({"Hostname":hostname})
    json.dump(allRules,output_file)
    output_file.write("\n")

def getKext(sipStatus,kextPath,output_file):
  kexts = os.listdir(kextPath)
  for kext in kexts:
    for root, dirs, files in os.walk(kextPath+"/"+kext, topdown=False):
      for name in files:
        kextDict = {}
        if name == ("Info.plist"):
          kextPlist = plistlib.readPlist(os.path.join(root, name))
          kextDict.update({"CFBundleName":kextPlist.get("CFBundleName")})
          kextDict.update({"CFBundleExecutable":kextPlist.get("CFBundleExecutable")})
          kextDict.update({"CFBundleIdentifier":kextPlist.get("CFBundleIdentifier")})
          kextDict.update({"OSBundleRequired":kextPlist.get("OSBundleRequired")})
          kextDict.update({"CFBundleGetInfoString":kextPlist.get("CFBundleGetInfoString")})
          kextDict.update({"Kext Path":os.path.join(root, name)})
          kextDict.update({"module":"Kernel Extensions"})
          kextDict.update({"Hostname":hostname})
          json.dump(kextDict,output_file)
          output_file.write("\n")
          #eachKext.update({os.path.join(root, name):kextDict})
  #add a check to do a codesign on the executable
  #AllKext.update({"Kexts":eachKext})
  #return AllKext

def getEnv(output_file):
  envVars = subprocess.Popen(["env"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].split('\n')
  for var in envVars:
    env = {}
    envValue = var.split("=")
    try:
      env.update({envValue[0]:envValue[1]})
    except:
      ""
    env.update({"module":"Environment Variables"})
    env.update({"Hostname":hostname})
    json.dump(env,output_file)
    output_file.write("\n")

def getLoginHooks(): #deprecated
  return True

def getPeriodicScripts(output_file):
  periodic = {}
  periodicDirs = ['/etc/periodic/daily/','/etc/periodic/weekly/','/etc/periodic/monthly/']
  for item in periodicDirs:
    periodicLst = []
    for root, dirs, files in os.walk(item, topdown=False):
      for name in files:
        periodicLst.append(name)
      periodic.update({item:periodicLst})
      periodic.update({"module":"Periodic Scripts"})
      periodic.update({"Hostname":hostname})
      json.dump(periodic,output_file)
      output_file.write("\n")

def getStartupScripts():
  #/Library/StartupItems and /System/Library/StartupItems
  return True

def getConnections(output_file):
  #get process listing with connections
  processes = subprocess.Popen(["lsof","-i"], stdout=subprocess.PIPE).communicate()[0].split('\n')
  lstofprcs = []
  for process in processes:
    processList = process.split(" ")
    tmplist = []
    #if a process has an established connection dump the contents in a new list
    if '(ESTABLISHED)' in processList:
      for item in processList:
        if len(item) > 0:
          tmplist.append(item)
      lstofprcs.append(tmplist)
  for process in lstofprcs:
    connections= {}
    connections.update({"Process Name":process[0]})
    connections.update({"Process ID":process[1]})
    connections.update({"User":process[2]})
    connections.update({"TCP/UDP":process[7]})
    connections.update({"Connection Flow":process[8]})
    connections.update({"module":"Established Connections"})
    connections.update({"Hostname":hostname})
    json.dump(connections,output_file)
    output_file.write("\n")

def SIPStatus(output_file):
  sip = {}
  status = subprocess.Popen(["csrutil","status"], stdout=subprocess.PIPE).communicate()[0]
  status = status.strip('\n').strip(".").split(":")[1].strip(" ")
  sip.update({"SIP Status":status})
  sip.update({"module":"System Intergrity Protection"})
  sip.update({"Hostname":hostname})
  json.dump(sip,output_file)
  outfile.write("\n")
  return sip
  

def GatekeeperStatus(output_file):
  gatekeeper = {}
  status = subprocess.Popen(["spctl","--status"], stdout=subprocess.PIPE).communicate()[0]
  gatekeeper.update({"Gatekeeper Status":status})
  gatekeeper.update({"module":"Gatekeeper Status"})
  gatekeeper.update({"Hostname":hostname})
  json.dump(gatekeeper,output_file)
  outfile.write("\n")

def getLoginItems(path,output_file):
  #Parsing - Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm
  loginItems = {}
  plist_file = path
  loginApps = []
  plist = Foundation.NSDictionary.dictionaryWithContentsOfFile_(plist_file)
  objects = plist.get("$objects")
  for item in objects:
    if item.isKindOfClass_(Foundation.NSClassFromString("NSDictionary")) == True:
      if item.has_key("NS.data"):
        bookmark = item.get("NS.data")
        properties = Foundation.NSURL.resourceValuesForKeys_fromBookmarkData_(['NSURLBookmarkAllPropertiesKey'],bookmark)
        loginApps.append(properties.get("NSURLBookmarkAllPropertiesKey").get("_NSURLPathKey"))
  loginApps = set(loginApps)
  loginApps = list(loginApps)
  loginItems.update({"Login Items":loginApps})
  loginItems.update({"module":"Login Items"})
  loginItems.update({"Hostname":hostname})
  json.dump(loginItems,output_file)
  outfile.write("\n")
  #return loginItems

def getApps(path,output_file):
  apps = {}
  app_lst = os.listdir(path)
  apps.update({"Applications":app_lst})
  apps.update({"module":"Applications"})
  apps.update({"Hostname":hostname})
  json.dump(apps,output_file)
  outfile.write("\n")
  return apps

def getEventTaps(output_file):
  evInfo = Quartz.CGGetEventTapList(10,None,None)
  for item in evInfo[1]:
    eventTap = {}
    eTap = str(item).strip("<").strip(">").split(" ")
    tappingProcess = eTap[5].split("=")[1]
    tappedProcess = eTap[6].split("=")[1]
    tappingProcName = subprocess.Popen(["ps", "-p", tappingProcess, "-o", "comm="], stdout=subprocess.PIPE).communicate()[0]
    eventTap.update({"eventTapID":eTap[1].split("=")[1]})
    eventTap.update({"Tapping Process ID":tappingProcess})
    eventTap.update({"Tapping Process Name":tappingProcName})
    eventTap.update({"Tapped Process ID":tappedProcess})
    eventTap.update({"Enabled":eTap[7].split("=")[1]})
    eventTap.update({"Module":"Event Taps"})
    json.dump(eventTap,output_file)
    outfile.write("\n")
  
def getBashHistory(output_file, users):
  userBashHistory = {}
  for user in users:
    history_file = '/Users/'+user+'/.bash_history'
    if os.path.isfile(history_file):
      with open(history_file, 'r') as bash_history:
        history_data = bash_history.read()
      history_data = history_data.split('\n')
      userBashHistory.update({"user":user})
      userBashHistory.update({"bash_commands":history_data})
      userBashHistory.update({"Module":"Bash History"})
      json.dump(userBashHistory,output_file)
      outfile.write("\n")
  



if __name__ == '__main__':
  output_list = []
  output = {}
  sipStatus = True

  outputFile = hostname
  outputDirectory = os.getcwd()


  parser = argparse.ArgumentParser(description='Helpful information for running your macOS Hunting Script.')
  parser.add_argument('-f',metavar='File Name',default=outputFile, help='Name of your output file (by default the name is: "data".')
  parser.add_argument('-d', metavar='Directory',default=outputDirectory, help='Directory of your output file (by default it is the current working directory.')
  parser.add_argument('-a', metavar='AWS Key', help='Your AWS Key if you want to upload to S3 bucket.')
  parser.add_argument('-n', action='store_true', help='Send nuke command to delete all files 24 hours after running script.')
  args = parser.parse_args()
  
  outputPath = args.d+"/"+args.f+".json"

  if not os.geteuid()==0:
    sys.exit('This script must be run as root!')


  with open(outputPath, 'w') as outfile:

    lst_of_users = getUsers(outfile).get("users")
    sipEnabled = SIPStatus(outfile).get("SIP Status")

  
    modules = [getSystemInfo(outfile),getInstallHistory(outfile),GatekeeperStatus(outfile),getConnections(outfile),
    getEnv(outfile),getPeriodicScripts(outfile), getCronJobs(lst_of_users,outfile),getEmond(outfile),getLaunchAgents('/Library/LaunchAgents',outfile),
    getLaunchDaemons('/Library/LaunchDaemons',outfile),getKext(sipStatus,'/Library/Extensions',outfile),getApps('/Applications',outfile),getEventTaps(outfile),getBashHistory(outfile,lst_of_users)]

    for module in modules:
      module

    #user specific modules
    for user in lst_of_users:
      userLaunchAgent = '/Users/'+user+'/Library/LaunchAgents'
      chromeEx = '/Users/'+user+'/Library/Application Support/Google/Chrome/Default/Extensions/'
      firefoxEx = '/Users/'+user+'/Library/Application Support/Firefox/'
      safariEx = '/Users/'+user+'/Library/Safari/Extensions'
      loginItemDir = '/Users/'+user+'/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm'
      apps_dir = '/Users/'+user+'/Applications'

      if os.path.exists(userLaunchAgent):
        getLaunchAgents(userLaunchAgent,outfile)
      if os.path.exists(chromeEx):
        getChromeExtensions(chromeEx,outfile)
      if os.path.exists(firefoxEx):
        getFirefoxExtensions(firefoxEx,outfile)
      if os.path.exists(safariEx):
        getSafariExtensions(safariEx,outfile)
      if os.path.exists(loginItemDir):
        getLoginItems(loginItemDir,outfile)
      if os.path.exists(apps_dir):
        getApps(apps_dir,outfile)

    if (sipEnabled != 'enabled'):
      sipStatus = False
    
    #if SIP is disabled, check for items in /System directory
    if sipStatus == False:
      output_list.append(getLaunchAgents('/System/Library/LaunchAgents',outfile))
      output_list.append(getLaunchDaemons('/System/Library/LaunchDaemons',outfile))
      output_list.append(getKext(sipStatus,'System/Library/Extensions',outfile))
