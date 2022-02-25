# macos-loginitems

A simple macOS LoginItems parser (and library) written in Rust!  
LoginItems are a form of persistence on macOS. They are triggered when a user logs into a system.  This simple library lets you parse this data.

LoginItems can be created for each macOS user, it can also be embedded in an Application. 

# Use Case
Parsing LoginItems on a macOS system is mainly useful for forensic investigtions. It can be used to identify possibly persistence on a system.  


# LoginItems Data
LoginItems contain a variety of intersting data such as:
1. Path to target binary
2. Target creation time
3. Volume UUID
4. Volume creation
5. Localized Name

LoginItems can exist per user at:
* `/Users/<USER>/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`  

And macOS Applications can bundle LoginItems which should be registered at:
* `/var/db/com.apple.xpc.launchd/loginitems.<UID>.plist`
Both files are PLIST files. However, `backgrounditems.btm` is a binary PLIST file that contains macOS Bookmark data. The Bookmark data contains the LoginItem

# References
http://michaellynn.github.io/2015/10/24/apples-bookmarkdata-exposed/  
https://mac-alias.readthedocs.io/en/latest/bookmark_fmt.html  
https://www.sentinelone.com/blog/how-malware-persists-on-macos/  
https://theevilbit.github.io/beyond/beyond_0003/  
