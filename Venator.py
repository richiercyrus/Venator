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
import ctypes
import ctypes.util
import objc
import platform

#get the hostname of the system the script is running on
hostname = socket.gethostname()

#get system information from the os
def getSystemInfo(output_file):
    system_data = {}
    uname = os.uname()
    macos_version = platform.mac_ver()[0]
    macos_arch = platform.mac_ver()[2]
    system_data.update({'hostname':uname[1]})
    system_data.update({'kernel':uname[2]})
    system_data.update({'kernel_release':uname[3].split(';')[1].split(':')[1]})
    system_data.update({'macOS_version':macos_version})
    system_data.update({'macOS_arch':macos_arch})
    system_data.update({"module":"system_info"})
    json.dump(system_data,output_file)
    outfile.write("\n")

# get the sha256 hash of any file
def getHash(file):
    import hashlib
    hasher = hashlib.sha256()
    with open(file, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return(hasher.hexdigest())

#Code used from https://github.com/synack/knockknock/blob/master/knockknock.py - Patrick Wardle! - to get the signing information for a given executable
def checkSignature(file, bundle=None): 
  SECURITY_FRAMEWORK = '/System/Library/Frameworks/Security.framework/Versions/Current/Security'
  kSecCSDefaultFlags = 0x0
  kSecCSDoNotValidateResources = 0x4
  kSecCSCheckAllArchitectures = 0x1
  kSecCSCheckNestedCode = 0x8
  kSecCSStrictValidate = 0x16
  kSecCSStrictValidate_kSecCSCheckAllArchitectures = 0x17
  kSecCSStrictValidate_kSecCSCheckAllArchitectures_kSecCSCheckNestedCode = 0x1f
  errSecSuccess = 0x0
  SecCSSignatureOK = errSecSuccess
  errSecCSUnsigned = -67062
  kPOSIXErrorEACCES = 100013
  kSecCSSigningInformation = 0x2
  kSecCodeInfoCertificates = 'certificates'

	#return dictionary
  signingInfo = {}
  sigCheckFlags = kSecCSStrictValidate_kSecCSCheckAllArchitectures_kSecCSCheckNestedCode 
  securityFramework = ctypes.cdll.LoadLibrary(SECURITY_FRAMEWORK)
  objcRuntime = ctypes.cdll.LoadLibrary(ctypes.util.find_library('objc'))
  objcRuntime.objc_getClass.restype = ctypes.c_void_p
  objcRuntime.sel_registerName.restype = ctypes.c_void_p
  status = not errSecSuccess
  signedStatus = None
  isApple = False
  authorities = []
  
  #print Foundation.NSString.stringWithString_(file)
	#file = Foundation.NSString.stringWithUTF8String_(file)
  file = Foundation.NSString.stringWithString_(file)
  file = file.stringByAddingPercentEscapesUsingEncoding_(Foundation.NSUTF8StringEncoding).encode('utf-8')
  path = Foundation.NSURL.URLWithString_(Foundation.NSString.stringWithUTF8String_(file))
  staticCode = ctypes.c_void_p(0)
  result = securityFramework.SecStaticCodeCreateWithPath(ctypes.c_void_p(objc.pyobjc_id(path)), kSecCSDefaultFlags, ctypes.byref(staticCode))
  signedStatus = securityFramework.SecStaticCodeCheckValidityWithErrors(staticCode, sigCheckFlags,None, None)
  if errSecSuccess == signedStatus:
		requirementReference = "anchor apple"
		NSString = objcRuntime.objc_getClass('NSString')
		objcRuntime.objc_msgSend.restype = ctypes.c_void_p
		objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
		requirementsString = objcRuntime.objc_msgSend(NSString, objcRuntime.sel_registerName('stringWithUTF8String:'), requirementReference)
		requirement = ctypes.c_void_p(0)
		if errSecSuccess == securityFramework.SecRequirementCreateWithString(ctypes.c_void_p(requirementsString), kSecCSDefaultFlags, ctypes.byref(requirement)):
			if errSecSuccess == securityFramework.SecStaticCodeCheckValidity(staticCode, sigCheckFlags, requirement):
				isApple = True

		information = ctypes.c_void_p(0)
		result = securityFramework.SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation,ctypes.byref(information))
		objcRuntime.objc_msgSend.restype = ctypes.c_void_p
		objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
		key = objcRuntime.objc_msgSend(NSString, objcRuntime.sel_registerName('stringWithUTF8String:'), kSecCodeInfoCertificates)
		objcRuntime.objc_msgSend.restype = ctypes.c_void_p
		objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
		certChain = objcRuntime.objc_msgSend(information, objcRuntime.sel_registerName('objectForKey:'), key)
		objcRuntime.objc_msgSend.restype = ctypes.c_uint
		objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
		count = objcRuntime.objc_msgSend(certChain, objcRuntime.sel_registerName('count'))
		certName = ctypes.c_char_p(0)
		for index in range(count):
			objcRuntime.objc_msgSend.restype = ctypes.c_void_p
			objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
			cert = objcRuntime.objc_msgSend(certChain, objcRuntime.sel_registerName('objectAtIndex:'), index)
			result = securityFramework.SecCertificateCopyCommonName(ctypes.c_void_p(cert), ctypes.byref(certName))
			if errSecSuccess != result:
				continue
			objcRuntime.objc_msgSend.restype = ctypes.c_char_p
			objcRuntime.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
			authorities.append(objcRuntime.objc_msgSend(certName, objcRuntime.sel_registerName('UTF8String')))

  status = errSecSuccess
  if signedStatus == 0:
    signingInfo['status'] = "signed"
  else:
    signingInfo['status'] = "unsigned"
  signingInfo['Apple binary'] = isApple
  signingInfo['Authority'] = authorities
  return (signingInfo)

def datetime_handler(x):
    if isinstance(x, datetime.datetime):
        return x.isoformat()
    #raise TypeError("Unknown type")

def parseAgentsDaemons(item,path):
  parsedPlist = {}
  plist_file = path+"/"+item
  plist_type = subprocess.Popen(["file", plist_file], stdout=subprocess.PIPE).communicate()
  #get the plist type
  plist_type = plist_type[0].split(":")[1].strip("\n").strip(" ")
  #if else the file is a binary plist, then we have to use external library to parse
  try:
    if plist_type == 'Apple binary property list':
      plist = Foundation.NSDictionary.dictionaryWithContentsOfFile_(plist_file)
    #elif plist_type == 'XML 1.0 document text, ASCII text':
      #plist = plistlib.readPlist(plist_file)
    elif plist_type == 'exported SGML document text, ASCII text':
      plist_text = subprocess.Popen(["cat", plist_file], stdout=subprocess.PIPE).communicate()
      #plist_text = plist_text[0].split("\n")
      if plist_text[0].split("\n")[0].startswith("<?xml"):
        #plist = plistlib.readPlist(plist_file)
        plist = plistlib.readPlistFromString(plist_text)
      else:
        xml_start = plist_text[0].find('<?xml')
        plist_string = plist_text[0][xml_start:]
        #del plist_text[0]
        #str1 = '\n'.join(plist_text)
        plist = plistlib.readPlistFromString(plist_string)
    #if the plist does not match any of the other types then update the dictionary and return it with a error.
    else:
      plist = plistlib.readPlist(plist_file)
    #else:
      #parsedPlist.update({'plist_format_error': ("Unknown plist type of "+plist_type+" for plist "+ plist_file)})
      #return parsedPlist
  except:
      parsedPlist.update({'plist_format_error': ("Unknown plist type of "+plist_type+" for plist "+ plist_file)})
      return parsedPlist

  progExecutableHash = ""
  try:
    if plist.get("ProgramArguments"):
      progExecutable = plist.get("ProgramArguments")[0]
      if os.path.exists(progExecutable):
        try:
          progExecutableHash = getHash(progExecutable)
        except:
          progExecutableHash = "Error hashing "+progExecutable
    elif plist.get("Program"):
      progExecutable = plist.get("Program")
      progExecutableHash = getHash(progExecutable)
      if progExecutable.startswith('REPLACE_HOME'):
        findHomeStart = plist_file.find("/Library")
        progExecutable = progExecutable.replace('REPLACE_HOME',plist_file[:findHomeStart])
        progExecutableHash = getHash(progExecutable)
  except:
    progExecutable = "Error parsing or no associated executable"
    progExecutableHash = "No executable to parse"
  
  if plist:
    if plist.get("RunAtLoad"):
      parsedPlist.update({'runAtLoad': str(plist.get("RunAtLoad"))})
    
    parsedPlist.update({'label': str(plist.get("Label"))})
    parsedPlist.update({'program': str(plist.get("Program"))})
    parsedPlist.update({'program_arguments': (str(plist.get("ProgramArguments"))).strip("[").strip("]")})
    parsedPlist.update({"signing_info":checkSignature(progExecutable)})
    parsedPlist.update({'hash':progExecutableHash}) 
    parsedPlist.update({'executable':progExecutable})
    parsedPlist.update({'plist_hash':getHash(plist_file)})
    parsedPlist.update({'path':plist_file})
    return parsedPlist

def getLaunchAgents(path,output_file):
    #get all of the launch agents at a specififc location returned into a list
    launchAgents = os.listdir(path)
    #for each of the launchAgents, parse the contents into a dictionary, add the name of the plist and the location to the dictionary
    for agent in launchAgents:
      parsedAgent = {}
      parsedAgent = parseAgentsDaemons(agent,path)
      #print progExecutable
      parsedAgent.update({"module":"launch_agents"})
      parsedAgent.update({"hostname":hostname})
      json.dump(parsedAgent,output_file)
      outfile.write("\n")
      
def getLaunchDaemons(path,output_file):
    launchDaemons = os.listdir(path)
    #parsedDaemon = {}
    #for each of the launchAgents, parse the contents into a dictionary, add the name of the plist and the location to the dictionary
    for daemon in launchDaemons:
      parsedDaemon = {}
      parsedDaemon = parseAgentsDaemons(daemon,path)
      parsedDaemon.update({"module":"launch_daemons"})
      parsedDaemon.update({"hostname":hostname})
      json.dump(parsedDaemon,output_file)
      outfile.write("\n") 

#get a list of users on the system      
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
    users_dict.update({"module":"users"})
    users_dict.update({"hostname":hostname})
    json.dump(users_dict,output_file)
    outfile.write("\n")
    return users_dict

#get all the safari extensions on the system
def getSafariExtensions(path,output_file):
  #safariExtensions = {}
  extension = []
  plist_file = path+'/Extensions.plist'
  plist = Foundation.NSDictionary.dictionaryWithContentsOfFile_(plist_file)
  if plist:
    for ext in plist.get("Installed Extensions"):
      safariExtensions = {}
      safariExtensions.update({"module":"safari_extensions"})  
      safariExtensions.update({'extension_name':ext.get("Archive File Name")})
      safariExtensions.update({'apple_signed':ext.get("Apple-signed")})
      safariExtensions.update({'developer_identifier':ext.get("Developer Identifier")})
      safariExtensions.update({'extension_path':plist_file})
      safariExtensions.update({"hostname":hostname})
      json.dump(safariExtensions,output_file)
      outfile.write("\n")

#get all chrome extensions on the system
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
               extensions.update({"extension_directory_name":directory})
               extensions.update({"extension_update_url":manifest_json.get("update_url").strip('u\'')})
               extensions.update({"extension_name":manifest_json.get("name").strip('u\'')})
               extensions.update({"module":"chrome_extensions"})
               extensions.update({"hostname":hostname})
               json.dump(extensions,output_file)
               outfile.write("\n")

#get all firefox extensions on the system
def getFirefoxExtensions(path,output_file):
  try:
    with open(path+"profiles.ini",'r') as profile_data:
      profile_dump = profile_data.read()
  except:
    return
  
  #extensions_path = profile_dump[profile_dump.find("Path="):profile_dump.find(".default")+8] 
  extensions_path = profile_dump[profile_dump.find("Path="):profile_dump.find("\\n")].split('\n')[0]
  extensions_path = extensions_path.split("=")[1]

  with open(path+extensions_path+"/extensions.json", 'r') as extensions:
    extensions_dump = extensions.read()
  extensions_json = json.loads(extensions_dump)

  for field in extensions_json.get("addons"):
    firefox_extensions = {}
    firefox_extensions.update({"extension_id": field.get("id")})
    firefox_extensions.update({"extension_update_url": field.get("updateURL")})
    firefox_extensions.update({"extension_options_url": field.get("optionsURL")})
    firefox_extensions.update({"extension_install_date": field.get("installDate")})
    firefox_extensions.update({"extension_last_updated": field.get("updateDate")})
    firefox_extensions.update({"extension_source_uri": field.get("sourceURI")})
    firefox_extensions.update({"extension_name": field.get("defaultLocale").get("name")})
    firefox_extensions.update({"extension_description": field.get("defaultLocale").get("description")})    
    firefox_extensions.update({"extension_creator": field.get("defaultLocale").get("creator")})
    firefox_extensions.update({"extension_homepage_url": field.get("defaultLocale").get("homepageURL")})
    firefox_extensions.update({"module":"firefox_extensions"})
    firefox_extensions.update({"hostname":hostname})        
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
  temporaryFiles.update({"hostname":hostname})
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
  downloadedFiles.update({"hostname":hostname})
  return downloadedFiles

def getInstallHistory(output_file):
  path = '/Library/Receipts/InstallHistory.plist'
  history = plistlib.readPlist(path)
  for item in history:
    tempdict = item
    installList = {}
    installList.update({"install_date":tempdict.get('date')})
    installList.update({"display_name":tempdict.get('displayName')})
    installList.update({"package_identifier":tempdict.get('packageIdentifiers')})
    installList.update({"module":"install_history"})
    installList.update({"hostname":hostname})
    json.dump(installList,output_file,default=datetime_handler,encoding='latin1')
    output_file.write("\n")
    

def getCronJobs(users,output_file):
  #get all of the current users
  usercrons = {}
  for user in users:
    #results in a tuple
    users_crontab = subprocess.Popen(["crontab","-u",user,"-l"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()
    #add user and associated crontabs to dict usercrons
    usercrons.update({"user":user})
    usercrons.update({"crontab":users_crontab})
    usercrons.update({"module":"cron_jobs"})
    usercrons.update({"hostname":hostname})
    json.dump(usercrons,output_file)
    output_file.write("\n")
  #cronJobs.update({"cronJobs":usercrons})
  #return cronJobs

def getEmond(output_file):
  emondRules = []
  allRules = {}
  for root, dirs, files in os.walk('/etc/emond.d/rules/', topdown=False):
    for name in files:
      emondRules.append(os.path.join(root, name))
  for rule in emondRules:
    allRules.update({rule:plistlib.readPlist(rule)})
    allRules.update({"rule":rule})
    allRules.update({"module":"emond_rules"})
    allRules.update({"hostname":hostname})
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
          kextDict.update({"kext_path":os.path.join(root, name)})
          kextDict.update({"module":"kernel_extensions"})
          kextDict.update({"hostname":hostname})
          json.dump(kextDict,output_file)
          output_file.write("\n")

def getEnv(output_file):
  envVars = subprocess.Popen(["env"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].split('\n')
  for var in envVars:
    env = {}
    envValue = var.split("=")
    if len(envValue) > 1:
      env.update({envValue[0]:envValue[1]})
      env.update({"module":"environment_variables"})
      env.update({"hostname":hostname})
      json.dump(env,output_file)
      output_file.write("\n")

def getPeriodicScripts(output_file):
  periodic = {}
  periodicDirs = ['/etc/periodic/daily/','/etc/periodic/weekly/','/etc/periodic/monthly/']
  for item in periodicDirs:
    periodicLst = []
    for root, dirs, files in os.walk(item, topdown=False):
      for name in files:
        periodicLst.append(name)
      periodic.update({item:periodicLst})
      periodic.update({"module":"periodic_scripts"})
      periodic.update({"hostname":hostname})
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
    connections.update({"process_name":process[0]})
    connections.update({"process_id":process[1]})
    connections.update({"user":process[2]})
    connections.update({"TCP_UDP":process[7]})
    connections.update({"connection_flow":process[8]})
    connections.update({"module":"established_connections"})
    connections.update({"hostname":hostname})
    json.dump(connections,output_file)
    output_file.write("\n")

def SIPStatus(output_file):
  sip = {}
  status = subprocess.Popen(["csrutil","status"], stdout=subprocess.PIPE).communicate()[0]
  status = status.strip('\n').strip(".").split(":")[1].strip(" ")
  sip.update({"sip_status":status})
  sip.update({"module":"system_intergrity_protection"})
  sip.update({"hostname":hostname})
  json.dump(sip,output_file)
  outfile.write("\n")
  return sip
  

def GatekeeperStatus(output_file):
  gatekeeper = {}
  status = subprocess.Popen(["spctl","--status"], stdout=subprocess.PIPE).communicate()[0]
  gatekeeper.update({"gatekeeper_status":status})
  gatekeeper.update({"module":"gatekeeper_status"})
  gatekeeper.update({"hostname":hostname})
  json.dump(gatekeeper,output_file)
  outfile.write("\n")

def parseApp(app):
  appInfo = {}
  appPlist = app+"/Contents/Info.plist"
  if os.path.exists(appPlist):
    plist_type = subprocess.Popen(["file", appPlist], stdout=subprocess.PIPE).communicate()
    plist_type = plist_type[0].split(":")[1].strip("\n").strip(" ")
    plist = None
    if plist_type == 'Apple binary property list':
      plist = Foundation.NSDictionary.dictionaryWithContentsOfFile_(appPlist)
      #elif (plist_type == 'XML 1.0 document text, ASCII text' or plist_type =='XML 1.0 document text, UTF-8 Unicode text'):
    elif "XML 1.0 document text" in plist_type:
      plist = plistlib.readPlist(appPlist)
    else:
      appInfo.update({"application":app})
      return appInfo
      
    executable = plist.get("CFBundleExecutable")
    executable_path = app+"/Contents/MacOS/"+executable
    
    if os.path.exists(executable_path):
      app_sig = checkSignature(executable_path,None)
      app_hash = getHash(executable_path)
    else:
      app_sig = "Parsing Error"
      app_hash = "Parsing Error"

    appInfo.update({"application":app})
    appInfo.update({"executable":executable})
    appInfo.update({"executable_path":executable_path})
    appInfo.update({"application_hash":app_hash})
    appInfo.update({"signature":app_sig})
  return appInfo

def getLoginItems(path,output_file):
  #Parsing - Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm
  plist_file = path
  loginApps = []
  plist = Foundation.NSDictionary.dictionaryWithContentsOfFile_(plist_file)
  objects = plist.get("$objects")
  for item in objects:
    if item.isKindOfClass_(Foundation.NSClassFromString("NSData")) == True:
      bookmark = item
      properties = Foundation.NSURL.resourceValuesForKeys_fromBookmarkData_(['NSURLBookmarkAllPropertiesKey'],bookmark)
      loginApps.append(properties.get("NSURLBookmarkAllPropertiesKey").get("_NSURLPathKey"))
    elif item.isKindOfClass_(Foundation.NSClassFromString("NSDictionary")) == True:
      if item.has_key("NS.data"):
        bookmark = item.get("NS.data")
        properties = Foundation.NSURL.resourceValuesForKeys_fromBookmarkData_(['NSURLBookmarkAllPropertiesKey'],bookmark)
        loginApps.append(properties.get("NSURLBookmarkAllPropertiesKey").get("_NSURLPathKey"))
  loginApps = set(loginApps)
  loginApps = list(loginApps)
  for item in loginApps:
    loginItems = {}
    #if there are apps in Login Items, parse them.
    if item:
      loginItems = parseApp(item)
      loginItems.update({"module":"login_items"})
      loginItems.update({"hostname":hostname})
      json.dump(loginItems,output_file)
      outfile.write("\n")

def getApps(path,output_file):
  app_lst = os.listdir(path)
  for app in app_lst:
    apps = {}
    app = path+"/"+app
    apps = parseApp(app)
    apps.update({"module":"applications"})
    apps.update({"hostname":hostname})
    json.dump(apps,output_file)
    outfile.write("\n")

def getEventTaps(output_file):
  evInfo = Quartz.CGGetEventTapList(10,None,None)
  for item in evInfo[1]:
    eventTap = {}
    eTap = str(item).strip("<").strip(">").split(" ")
    tappingProcess = eTap[5].split("=")[1]
    tappedProcess = eTap[6].split("=")[1]
    tappingProcName = subprocess.Popen(["ps", "-p", tappingProcess, "-o", "comm="], stdout=subprocess.PIPE).communicate()[0]
    eventTap.update({"eventTapID":eTap[1].split("=")[1]})
    eventTap.update({"hostname":hostname})
    eventTap.update({"tapping_process_id":tappingProcess})
    eventTap.update({"tapping_process_name":tappingProcName})
    eventTap.update({"tapped_process_id":tappedProcess})
    eventTap.update({"enabled":eTap[7].split("=")[1]})
    eventTap.update({"module":"event_taps"})
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
      userBashHistory.update({"hostname":hostname})
      userBashHistory.update({"bash_commands":history_data})
      userBashHistory.update({"module":"bash_history"})
      json.dump(userBashHistory,output_file)
      outfile.write("\n")


if __name__ == '__main__':
  output_list = []
  output = {}
  sipStatus = True

  outputFile = hostname
  outputDirectory = os.getcwd()
  print(""" 
__     __               _
\ \   / /__ _ __   __ _| |_ ___  _ __
 \ \ / / _ \ '_ \ / _` | __/ _ \| '__|
  \ V /  __/ | | | (_| | || (_) | |
   \_/ \___|_| |_|\__,_|\__\___/|_|
          """)
  


  parser = argparse.ArgumentParser(description='Helpful information for running your macOS Hunting Script.')
  parser.add_argument('-f',metavar='File Name',default=outputFile, help='Name of your output file (by default the name is the hostname of the system).')
  parser.add_argument('-d', metavar='Directory',default=outputDirectory, help='Directory of your output file (by default it is the current working directory).')
  parser.add_argument('-a', metavar='AWS Key', help='Your AWS Key if you want to upload to S3 bucket.')
  args = parser.parse_args()
  
  outputPath = args.d+"/"+args.f+".json"

  if not os.geteuid()==0:
    sys.exit('This script must be run as root!')


  with open(outputPath, 'w') as outfile:

    lst_of_users = getUsers(outfile).get("users")
    sipEnabled = SIPStatus(outfile).get("sip_status")

  
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
      output_list.append(getKext(sipStatus,'/System/Library/Extensions',outfile))
