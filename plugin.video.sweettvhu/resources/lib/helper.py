import json

import base64
import hashlib
import sys, io, os
import calendar
from datetime import datetime, timedelta
import time
import collections
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import iso8601
import requests
try:
    # Python 3
    from urllib.parse import quote, unquote
except:
    # Python 2 (Kodi 18)
    from urllib import quote, unquote
try:
    import pytz
except:
    pytz = None

import xbmc
import xbmcgui
import xbmcvfs
import xbmcaddon
import xbmcplugin

from resources.lib.brotlipython import brotlidec

DEBUG = False

def debug_log(msg):
    if DEBUG:
        xbmc.log(f'[Helper DEBUG] {msg}', level=xbmc.LOGDEBUG)


def resp_text(resp):
    """Return decoded response text."""
    if resp and resp.headers.get('content-encoding') == 'br':
        out = []
        # terrible implementation but it's pure Python
        return brotlidec(resp.content, out).decode('utf-8')
    response_content = resp.text

    return response_content.replace("\'",'"')

class Helper:
    def __init__(self, base_url=None, handle=None):
        self.base_url = base_url if base_url else sys.argv[0]
        self.handle = int(handle) if handle is not None else int(sys.argv[1])        
        self.addon = xbmcaddon.Addon()
        self.addon_name = xbmcaddon.Addon().getAddonInfo('id')
        self.addon_version = xbmcaddon.Addon().getAddonInfo('version')
        self.datapath = self.translate_path(self.get_path('profile'))
        
        self.art = {'icon': self.addon.getAddonInfo('icon'),
                    'fanart': self.addon.getAddonInfo('fanart'),
                }
        
        
        
        self.proxyport = self.get_setting('proxyport')

        try:
            self.kukis = self.load_file(self.datapath+'kukis', isJSON=True)
        except:
            self.kukis = {}
            
        self._sess = None
        self.kuk = {}

        # API
        
        self.base_api_url = 'https://api.sweet.tv/{}'#SigninService/Email.json'  'https://kanalsportowy.pl/api/{}'
       # self.main_page = self.base_api_url.format('products/sections/main')

        self.auth_url = self.base_api_url.format('SigninService/Email.json')
        self.token_url = self.base_api_url.format('AuthenticationService/Token.json')
        self.UA = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'   
        self.version = "4.0.54"  
        self.version_code = 1
        self.params = {}

        # --- UUID BETÖLTÉS / GENERÁLÁS ---
        self.uuid = self.get_setting('uuid')

        xbmc.log("[SweetTV DEBUG] Device UUID: %s" % self.uuid, xbmc.LOGINFO)        
        # --- LOGIN ADATOK BETÖLTÉS ---
        self.username = self.get_setting('username')
        self.password = self.get_setting('password')
        self.subtitles = self.get_setting('subtitles')

        # --- AUTO DECRYPT ---
        self.username = self.auto_decrypt(self.username)
        self.password = self.auto_decrypt(self.password)

        # self.API_CorrelationId = self.get_setting('CorrelationId')
        self.bearer = self.get_setting('bearer')
        self.refresh_token = self.get_setting('refresh_token')or None
        self.logged = self.get_setting('logged')

        # --- Bearer normalizálás ---
        if self.bearer:
            if not self.bearer.startswith("Bearer "):
                self.bearer = "Bearer " + self.bearer

            # Debug safe (Python2 kompatibilis)
            xbmc.log("[SweetTV DEBUG] Bearer header set: %s" % (self.bearer[:40] if self.bearer else "NONE"), xbmc.LOGINFO)
        self.headers = {
            'Host': 'api.sweet.tv',
            'user-agent': self.UA,          
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'hu',
            'x-device': '1;22;0;2;'+ self.version,
            'origin': 'https://sweet.tv',
            'dnt': '1',
            'referer': 'https://sweet.tv/',
        }
        if self.bearer:
            self.headers["authorization"] = self.bearer    
    def token_expired(self):
        token_time = int(self.get_setting("token_time") or 0)
        expires_in = int(self.get_setting("expires_in") or 3600)
        now = int(time.time())

        if token_time == 0:
            xbmc.log("[SweetTV] Nincs token_time → login szükséges", xbmc.LOGINFO)
            return True

        marad = expires_in - (now - token_time)
        xbmc.log("[SweetTV DEBUG] Token hátralévő idő: %d mp" % marad, xbmc.LOGINFO)

        return (now - token_time) > (expires_in *0.85)   
    def refreshToken(self):
        xbmc.log("[SweetTV DEBUG] Token frissítés indítása", xbmc.LOGINFO)
        self.notification("SweetTV", "Token frissítés folyamatban…")

        refresh_token_val = self.get_setting("refresh_token")
        if not refresh_token_val:
            xbmc.log("[SweetTV HIBA] Nincs elérhető refresh_token!", xbmc.LOGERROR)
            self.notification("SweetTV", "Nincs elérhető refresh_token!")
            return False

        json_data = {
            'device': {
                'type': 'DT_Android_Player',               
                'application': {
                    'type': 'AT_SWEET_TV_Player',
                },
                'model': 'self.UA',                
                    'firmware': {
                    'versionCode': self.version_code,               
                'versionString': self.version,             
                },
                'uuid': self.uuid,
                'supported_drm': {
                    'widevine_modular': True,
                }, 
                'screen_info': {
                    'aspectRatio': 6,
                    'width': 2048,
                    'height': 1152,
                },
            },
            'refresh_token': refresh_token_val,
        }

        try:
            jsdata = self.request_sess(
                self.token_url,
                'post',
                headers=self.headers,
                data=json_data,
                is_json=True,
                json_data=True,
                skip_token_check=True
            )

            xbmc.log("[SweetTV DEBUG] refreshToken válasz: %s" % str(jsdata), xbmc.LOGDEBUG)

            if not jsdata or not isinstance(jsdata, dict) or not jsdata.get("access_token"):              
                xbmc.log("[SweetTV HIBA] Refresh válasz hibás: %s" % str(jsdata), xbmc.LOGERROR)
                self.notification("SweetTV", "Token frissítés sikertelen!")
    
                # ← Törlés tokenekből
                self.set_setting("bearer", "")
                self.set_setting("refresh_token", "")
                self.set_setting("token_time", "")
                self.set_setting("expires_in", "")
                self.bearer = None
                self.refresh_token = None
                self._sess = None

                return False        
                
            access_token = jsdata.get("access_token")
            refresh_token = jsdata.get("refresh_token")
            expires_in = jsdata.get("expires_in") or jsdata.get("expiresIn") or 3600

            if not access_token or not refresh_token:
                xbmc.log("[SweetTV HIBA] Token hiányzik a válaszból", xbmc.LOGERROR)
                self.notification("SweetTV", "Token frissítés sikertelen (hiányzó token)")

                # ← Törlés tokenekből
                self.set_setting("bearer", "")
                self.set_setting("refresh_token", "")
                self.set_setting("token_time", "")
                self.set_setting("expires_in", "")
                self.bearer = None
                self.refresh_token = None
                self._sess = None

                return False

            bearer = "Bearer " + access_token

            # SAVE SETTINGS
            self.bearer = "Bearer " + access_token           
            self.set_setting("bearer", self.bearer)
            self.set_setting("refresh_token", refresh_token)
            self.set_setting("expires_in", str(expires_in))
            self.set_setting("token_time", str(int(time.time())))
            # RAM
            self.headers["authorization"] = self.bearer            
            self.refresh_token = refresh_token
            # REQUEST SESSION UPDATE
            if self._sess:
                self._sess.headers.update({"authorization":self.bearer})               
                xbmc.log("[SweetTV DEBUG] Session Bearer frissítve", xbmc.LOGINFO)

            xbmc.log(f"[SweetTV DEBUG] Bearer frissítve: {bearer[:50]}", xbmc.LOGINFO)
            self.notification("SweetTV", "Token sikeresen frissítve")
            return True

        except Exception as e:
            xbmc.log("[SweetTV HIBA] Token frissítés kivétel: %s" % str(e), xbmc.LOGERROR)
            self.notification("SweetTV", "Token frissítés kivétel történt")

            # ← Törlés tokenekből
            self.set_setting("bearer", "")
            self.set_setting("refresh_token", "")
            self.set_setting("token_time", "")
            self.set_setting("expires_in", "")
            self.bearer = None
            self.refresh_token = None
            self._sess = None

            return False

    def do_login(self):
        xbmc.log("===== [SweetTV DEBUG] Login indítása =====", xbmc.LOGINFO)

        # --- Felhasználónév / jelszó ellenőrzés ---
        if not self.username or not self.password:
            xbmc.log("[SweetTV HIBA] Nincs megadva felhasználónév vagy jelszó!", xbmc.LOGERROR)
            self.notification("SweetTV", "Hiányoznak a bejelentkezési adatok!")
            self.set_setting('logged', 'false')
            return False

        # --- Login JSON ---
        json_data = {
            'device': {
                'type': 'DT_Android_Player',           
                'application': {'type': 'AT_SWEET_TV_Player'},
                'model': 'self.UA',               
                'firmware': {'versionCode': self.version_code,               
                    'versionString': self.version},
                'uuid': self.uuid,
                'supported_drm': {'widevine_modular': True},
                'screen_info': {'aspectRatio': 6, 'width': 2048, 'height': 1152},
            },
            'email': self.username,
            'password': self.password,
        }


        try:
            jsdata = self.request_sess(
                self.auth_url,
                'post',
                headers=self.headers,
                data=json_data,
                is_json=True,
                json_data=True,
                skip_token_check=True
            )
        except Exception as e:
            xbmc.log("[SweetTV HIBA] Login kérés sikertelen: %s" % str(e), xbmc.LOGERROR)
            self.notification("SweetTV Hiba", "API kapcsolat sikertelen!")
            self.set_setting('logged', 'false')
            return False

        xbmc.log("[SweetTV DEBUG] API válasz: %s" % str(jsdata), xbmc.LOGINFO)

        # --- API result ellenőrzés ---
        if not jsdata or not isinstance(jsdata, dict) or jsdata.get("result") != "OK":
            xbmc.log("[SweetTV HIBA] API ERROR választ adott: %s" % str(jsdata), xbmc.LOGERROR)
            self.notification("SweetTV Hiba", "[COLOR gold]Bejelentkezés sikertelen![/COLOR]")
            self.set_setting("logged", "false")
            return False
        # --- Token mezők ---
        access_token  = jsdata.get("accessToken") or jsdata.get("access_token")
        refresh_token = jsdata.get("refreshToken") or jsdata.get("refresh_token")
        expires_in = jsdata.get("expiresIn") or jsdata.get("expires_in") or 3600

        if not access_token:
            xbmc.log("[SweetTV HIBA] Nincs access_token a válaszban!", xbmc.LOGERROR)
            self.set_setting("logged", "false")
            return False
        # --- Sikeres login ---
        bearer_value = "Bearer " + str(access_token)

        # Beállítások mentése – csak a raw access_token mentése!
        self.bearer = bearer_value      
        self.set_setting("bearer", self.bearer)
        self.set_setting("refresh_token", str(refresh_token))
        self.set_setting("expires_in", str(expires_in))
        self.set_setting("token_time", str(int(time.time())))
        self.set_setting("logged", "true")

        # RAM frissítés – headerbe mindig prefix
        self.headers["authorization"] = self.bearer       
        if self._sess:
            self._sess.headers.update({"authorization": self.bearer})
        # Email / jelszó titkosított mentése
        try:
            self.set_setting("username", self.encrypt_pw(self.username))
            self.set_setting("password", self.encrypt_pw(self.password))
            xbmc.log("[SweetTV DEBUG] Login adatok titkosítva és elmentve", xbmc.LOGINFO)
        except Exception as e:
            xbmc.log("[SweetTV HIBA] Encrypt save fail: %s" % str(e), xbmc.LOGERROR)

        xbmc.log("[SweetTV INFO] Sikeres bejelentkezés!", xbmc.LOGINFO)
        self.notification("SweetTV", "[COLOR lime]Sikeres bejelentkezés![/COLOR]")
        self.refresh()

        return True

    def ensure_token(self):
        try:
            setting = str(self.get_setting("logged")).lower()

            if setting != "true":
                xbmc.log("[SweetTV] logged flag false → login szükséges", xbmc.LOGINFO)
                return self.do_login()
            if not self.bearer:
                xbmc.log("[SweetTV] Nincs bearer → login", xbmc.LOGINFO)
                return self.do_login()

            if self.token_expired():
                xbmc.log("[SweetTV] Token expired", xbmc.LOGINFO)

                if self.refresh_token and len(self.refresh_token) > 10:
                    if not self.refreshToken():
                        xbmc.log("[SweetTV] Refresh sikertelen → login", xbmc.LOGINFO)
                        return self.do_login()
                else:
                    return self.do_login()

            return True

        except Exception as e:
            xbmc.log(f"[SweetTV HIBA] ensure_token: {e}", xbmc.LOGERROR)
            return False
    @property
    def sess(self):
        if self._sess is None:
            self._sess = requests.Session()

            if self.kukis:
                self._sess.cookies.update(self.kukis)
                self._sess.cookies.update(self.kuk)

            if self.bearer:
                self._sess.headers.update({"authorization": self.bearer})
                xbmc.log("[SweetTV] Bearer token betöltve a session-be", xbmc.LOGINFO)

        return self._sess   
    def input_dialog(self, text, typ=None):
        typ = xbmcgui.INPUT_ALPHANUM if not typ else typ
        return xbmcgui.Dialog().input(text, type=typ)
        
    def get_path(self ,data):    
        return self.addon.getAddonInfo(data)
        
    def translate_path(self ,data):
        try:
            return xbmcvfs.translatePath(data)
        except:
            return xbmc.translatePath(data).decode('utf-8')
            
    def save_file(self, file, data, isJSON=False):
        with io.open(file, 'w', encoding="utf-8") as f:
            if isJSON == True:
                str_ = json.dumps(data,indent=4, sort_keys=True,separators=(',', ': '), ensure_ascii=False)
                f.write(str(str_))
            else:
                f.write(data)

    def load_file(self, file, isJSON=False):

        if not os.path.isfile(file):
            return None
    
        with io.open(file, 'r', encoding='utf-8') as f:
            if isJSON == True:
                return json.load(f, object_pairs_hook=collections.OrderedDict)
            else:
                return f.read() 

# ===== PASSWORD OBFUSCATION =====
    def _get_key(self):
        uuid = self.uuid or "default_uuid"
        salt = "SWEETTV_HARDCORE_2026"
        return hashlib.sha256((uuid + salt).encode('utf-8')).digest()

    def encrypt_pw(self, pw):
        if not pw:
            return ""
        key = self._get_key()
        data = pw.encode('utf-8')
        enc = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
        return base64.b64encode(enc).decode('utf-8')

    def decrypt_pw(self, enc):
        if not enc:
            return ""
        key = self._get_key()
        try:
            data = base64.b64decode(enc)
            dec = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
            return dec.decode('utf-8')
        except:
            return enc  # fallback ha plain text volt

    # --- AUTOMATIKUS DECRYPT régi/új logika ---
    def auto_decrypt(self, pw):
        if not pw:
            return ""
        try:
            # Próbáljuk az új _get_key() logikával
            return self.decrypt_pw(pw)
        except Exception:
            # Ha nem megy, plain text fallback
            return pw        
    def get_setting(self, setting_id):
        setting = xbmcaddon.Addon(self.addon_name).getSetting(setting_id)
        if setting == 'true':
            return True
        elif setting == 'false':
            return False
        else:
            return setting
    
    def set_setting(self, key, value):
        return xbmcaddon.Addon(self.addon_name).setSetting(key, value)
        
        
    def open_settings(self):
        xbmcaddon.Addon(self.addon_name).openSettings()

    def sleep(self, seconds):
        return xbmc.sleep(int(seconds))    

    def dialog_select(self, heading, label):
        return xbmcgui.Dialog().select(heading,label)
        
    def dialog_multiselect(self, heading, label):
        return xbmcgui.Dialog().dialog_multiselect(heading,label)
        
    def dialog_choice(self, heading, message, agree, disagree):
        return xbmcgui.Dialog().yesno(heading, message, yeslabel=agree, nolabel=disagree)
        
        
    def add_item(self, title, url, playable=False, info=None, art=None, content=None, folder=True, contextmenu = None):

        list_item = xbmcgui.ListItem(label=title)
        if playable:
            list_item.setProperty('IsPlayable', 'true')
            folder = False
        if art:
            list_item.setArt(art)
        else:
            art = {
                'icon': self.addon.getAddonInfo('icon'),
                'fanart': self.addon.getAddonInfo('fanart')
            }
            list_item.setArt(art)
        if info:
            list_item.setInfo('Video', info)
        if content:
            xbmcplugin.setContent(self.handle, content)
        if contextmenu:
            list_item.addContextMenuItems(contextmenu, replaceItems=True)
        xbmcplugin.addDirectoryItem(self.handle, url, list_item, isFolder=folder)

    def eod(self, cache=True):
        xbmcplugin.endOfDirectory(self.handle, cacheToDisc=cache)

    def refresh(self):
        return xbmc.executebuiltin('Container.Refresh()')
        
    def update(self,func=''):
        return xbmc.executebuiltin('Container.Refresh(%s)'%func)
        
    def updatex(self,func=''):
        return xbmc.executebuiltin('Container.Update(%s)'%func) 
       
    def runplugin(self,func=''):
        return xbmc.executebuiltin('RunPlugin(%s)'%func)
        
    def notification(self, heading, message):
        xbmcgui.Dialog().notification(heading, message, time=3000)

    def request_sess(self, url, method='get', data=None, headers=None, cookies=None, params=None,
                 result=True, is_json=False, allow=True, json_data=False, skip_token_check=False):

        data = data or {}
        headers = headers.copy() if headers else {}        
        cookies = cookies or {}
        params = params or self.params

        # --- Token biztosítása ---
        if not skip_token_check:
            if not self.ensure_token():
                xbmc.log("[SweetTV ERROR] Token nem biztosítható, request megszakítva", xbmc.LOGERROR)
                return {}

        # --- Authorization ide ---
        if self.bearer:
            headers["authorization"] = self.bearer


        # --- HTTP session init ---
        sess = self.sess
        
        xbmc.log(f"[SweetTV DEBUG] Kérés → {method.upper()} {url}", xbmc.LOGINFO)

        max_retries = 2
        for attempt in range(max_retries):           
            try:
                # ===== HTTP KÉRÉS =====
                if method.lower() == 'get':
                    resp = sess.get(url, headers=headers, cookies=cookies,
                                    timeout=5, params=params, verify=False, allow_redirects=allow)
                elif method.lower() == 'post':
                    if json_data:
                        resp = sess.post(url, headers=headers, json=data, cookies=cookies,
                                     timeout=5, params=params, verify=False, allow_redirects=allow)
                    else:
                        resp = sess.post(url, headers=headers, data=data, cookies=cookies,
                                     timeout=5, params=params, verify=False, allow_redirects=allow)
                elif method.lower() == 'delete':
                    resp = sess.delete(url, headers=headers, cookies=cookies,
                                   timeout=5, params=params, verify=False, allow_redirects=allow)
                else:
                    raise Exception("Unsupported HTTP method")

                xbmc.log(f"[SweetTV DEBUG] HTTP státusz: {resp.status_code}", xbmc.LOGINFO)

                # ===== 401 / code16 TOKEN KEZELÉS =====
                retry_token = False

                # 401 → Bearer token lejárt
                if resp.status_code == 401:
                    xbmc.log("[SweetTV INFO] 401 → Token lejárt, próbáljuk frissíteni...", xbmc.LOGINFO)
                    retry_token = True

                # code16 → SweetTV API kéri a token frissítését
                elif is_json:
                    try:
                        dataj = resp.json()
                        if isinstance(dataj, dict) and dataj.get("code") == 16:
                            xbmc.log("[SweetTV INFO] API code=16 → Token refresh", xbmc.LOGINFO)
                            retry_token = True
                    except Exception as e:
                        xbmc.log(f"[SweetTV DEBUG] JSON parse fail code16 check: {e}", xbmc.LOGDEBUG)
                        dataj = {}

                # Ha szükséges a token frissítés / új login
                if retry_token:
                    if self.refreshToken():
                        headers["authorization"] = self.bearer
                        xbmc.log("[SweetTV INFO] Token refresh sikeres", xbmc.LOGINFO)
                        continue
                    elif self.do_login():
                        headers["authorization"] = self.bearer
                        xbmc.log("[SweetTV INFO] Új login sikeres", xbmc.LOGINFO)
                        continue
                    else:
                        xbmc.log("[SweetTV HIBA] Token refresh és login is sikertelen", xbmc.LOGERROR)
                        return {}
                # ===== 403 Block =====
                if resp.status_code == 403:
                    xbmc.log("[SweetTV WARNING] 403 Cloudflare / bot védelem!", xbmc.LOGERROR)
                    xbmc.log(resp.text[:300], xbmc.LOGERROR)
                    return {}

                # ===== HTTP hiba ellenőrzés =====
                try:
                    resp.raise_for_status()
                except requests.HTTPError as e:
                    xbmc.log(f"[SweetTV ERROR] HTTP hiba: {e}", xbmc.LOGERROR)
                    return {} if result else resp_text(resp)

                # ===== RESPONSE PARSING =====
                if is_json:
                    try:
                        dataj = resp.json()
                        return dataj if result else resp
                    except Exception as e:
                        xbmc.log(f"[SweetTV ERROR] JSON decode fail: {e}", xbmc.LOGERROR)
                        return {} if result else resp_text(resp)

                # Ha nem JSON, sima szöveg
                return resp_text(resp) if result else resp
                
            except Exception as e:
                xbmc.log(f"[SweetTV HIBA] request_sess fail ({attempt+1}/{max_retries}): {e}", xbmc.LOGERROR)
                time.sleep(1)

        xbmc.log("[SweetTV KRITIKUS] API nem elérhető, visszatérés üres dict-el", xbmc.LOGERROR)
        return {}
        
    def PlayVid (self, mpdurl, lic_url='', PROTOCOL='', DRM='', certificate = '', flags=True, subs = None, vod=False):
        from inputstreamhelper import Helper as ISHelper      
        play_item = xbmcgui.ListItem(path=mpdurl)

        if subs:
            play_item.setSubtitles(subs)

        if PROTOCOL:
            is_helper = ISHelper(PROTOCOL, drm=DRM)    

            if is_helper.check_inputstream():
                if sys.version_info >= (3,0,0):
                    play_item.setProperty('inputstream', is_helper.inputstream_addon)
                else:
                    play_item.setProperty('inputstreamaddon', is_helper.inputstream_addon)
                if 'mpd' in PROTOCOL:
                    play_item.setMimeType('application/dash+xml')
                else:
                    play_item.setMimeType('application/vnd.apple.mpegurl')
                play_item.setProperty('inputstream.adaptive.manifest_type', PROTOCOL)
                play_item.setProperty('inputstream.adaptive.manifest_headers', 'User-Agent='+quote(self.UA)+'&Referer='+quote('https://sweet.tv/'))
                play_item.setProperty('inputstream.adaptive.stream_headers', 'User-Agent='+quote(self.UA)+'&Referer='+quote('https://sweet.tv/'))
                
                if vod==True:
                    play_item.setProperty('ResumeTime', '1')
                    play_item.setProperty('TotalTime', '1')

                if DRM and lic_url:
                    play_item.setProperty('inputstream.adaptive.license_type', DRM)
                    play_item.setProperty('inputstream.adaptive.manifest_update_parameter', 'full')
                    play_item.setProperty('inputstream.adaptive.license_key', lic_url)
                    if certificate:
                        play_item.setProperty('inputstream.adaptive.server_certificate', certificate)
                if flags:
                    play_item.setProperty('inputstream.adaptive.license_flags', "persistent_storage")
                play_item.setContentLookup(False)
                

        xbmcplugin.setResolvedUrl(self.handle, True, listitem=play_item)
        
    def ffmpeg_player(self, stream_url):
        
        sURL=stream_url+'|User-Agent='+quote(self.UA)+'&Referer='+quote('https://sweet.tv/')
        play_item = xbmcgui.ListItem(path=sURL)
        xbmcplugin.setResolvedUrl(self.handle, True, listitem=play_item)
    
    def formatTime(self, czas, format):
        try:
            dt = self.parse_datetime(czas, localize=True)
            return dt.strftime('%H:%M')
        except:
            return czas

    def CreateDays(self):
        now = self.timeNow()
        timestamp = int(now.timestamp())

        dnitygodnia_hu = ["hétfő", "kedd", "szerda", "csütörtök", "péntek", "szombat", "vasárnap"]

        out = []
        for i in range(timestamp, timestamp - 30*86400, -86400):
            x_utc = datetime.utcfromtimestamp(i)
            x_local = self.utc_to_local(x_utc)
            day_name = dnitygodnia_hu[x_local.weekday()]
            day_str = x_local.strftime('%d.%m')
            start = x_utc.strftime('%Y-%m-%dT00:00:00')
            end = x_utc.strftime('%Y-%m-%dT23:59:59')
            dod = f'&start_after_time={start}Z&start_before_time={end}Z'
            out.append({'dzien': f'{day_name} {day_str}', 'dodane': dod})
        return out
    def timeNow(self, query=False):
        if pytz:
            tz = pytz.timezone("Europe/Budapest")
            now = datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(tz)
        else:
            # Fallback Kodi (nem DST safe)
            now = datetime.now()

        if query:
            day = now.strftime('%Y-%m-%d')
            offset = now.strftime('%z')  # +0100 vagy +0200
            offset = quote(offset)
            return (
                f'&since={day}T00%3A00{offset}'
                f'&till={day}T23%3A59{offset}'
            )

        return now    

    def string_to_date(self, string, string_format):
        dt = self.parse_datetime(string)
        if dt:
            return dt.strftime(string_format)
        return string
    def parse_datetime(self, iso8601_string, localize=True):
        try:
            import iso8601
            datetime_obj = iso8601.parse_date(iso8601_string)
        except (ImportError, Exception):
            # Fallback, ha iso8601 nincs
            try:
                # Például: '2026-02-18T14:30:00.123Z' vagy '2026-02-18T14:30:00Z'
                dt_str = iso8601_string.rstrip("Z")
                dt_format = "%Y-%m-%dT%H:%M:%S.%f" if "." in dt_str else "%Y-%m-%dT%H:%M:%S"
                datetime_obj = datetime.strptime(dt_str, dt_format)
            except Exception as e:
                debug_log(f"parse_datetime fallback failed: {iso8601_string} → {e}")
                return None

        if localize:
            return self.utc_to_local(datetime_obj)
        return datetime_obj

    @staticmethod
    def to_timestamp(a_date):
        if a_date.tzinfo:
            epoch = datetime(1970, 1, 1, tzinfo=pytz.UTC)
            diff = a_date.astimezone(pytz.UTC) - epoch
        else:
            epoch = datetime(1970, 1, 1)
            diff = a_date - epoch
        return int(diff.total_seconds()) * 1000
    @staticmethod
    def utc_to_local(utc_dt):
        try:
            import pytz
            tz = pytz.timezone("Europe/Budapest")
            return utc_dt.replace(tzinfo=pytz.utc).astimezone(tz)
        except:
            return datetime.fromtimestamp(calendar.timegm(utc_dt.timetuple()))