Change "path" to actual absolute path to uapki-hostapp.

On WINDOWS add path to manifest to registry (system-wide):
Google Chrome: HKLM\Software\Google\Chrome\NativeMessagingHosts\com.sit.uapki.hostapp"; ValueType: string; ValueData: "{path}\uapki-hostapp-chrome.json"
Firefox: HKLM\Software\Mozilla\NativeMessagingHosts\com.sit.uapki.hostapp"; ValueType: string; ValueData: "{path}\uapki-hostapp-firefox.json"

On WINDOWS add path to manifest to registry (user-specific):
Google Chrome: HKCU\Software\Google\Chrome\NativeMessagingHosts\com.sit.uapki.hostapp"; ValueType: string; ValueData: "{path}\uapki-hostapp-chrome.json"
Firefox: HKCU\Software\Mozilla\NativeMessagingHosts\com.sit.uapki.hostapp"; ValueType: string; ValueData: "{path}\uapki-hostapp-firefox.json"

On Linux (system-wide):
Google Chrome: /etc/opt/chrome/native-messaging-hosts/uapki-hostapp-chrome.json
Chromium: /etc/chromium/native-messaging-hosts/uapki-hostapp-chrome.json
Firefox: /usr/lib/mozilla/native-messaging-hosts/uapki-hostapp-firefox.json
or       /usr/lib64/mozilla/native-messaging-hosts/uapki-hostapp-firefox.json

On Linux (user-specific, default path):
Google Chrome: ~/.config/google-chrome/NativeMessagingHosts/uapki-hostapp-chrome.json
Chromium: ~/.config/chromium/NativeMessagingHosts/uapki-hostapp-chrome.json
Firefox: ~/.mozilla/native-messaging-hosts/uapki-hostapp-firefox.json

On macOS (system-wide):
Google Chrome: /Library/Google/Chrome/NativeMessagingHosts/uapki-hostapp-chrome.json
Chromium: /Library/Google/Chrome/NativeMessagingHosts/uapki-hostapp-chrome.json 
Firefox: /Library/Application Support/Mozilla/NativeMessagingHosts/uapki-hostapp-firefox.json

On macOS (user-specific, default path):
Google Chrome: ~/Library/Application Support/Google/Chrome/NativeMessagingHosts/uapki-hostapp-chrome.json
Chromium: ~/Library/Application Support/Chromium/NativeMessagingHosts/uapki-hostapp-chrome.json
Firefox: ~/Library/Application Support/Mozilla/NativeMessagingHosts/uapki-hostapp-firefox.json
