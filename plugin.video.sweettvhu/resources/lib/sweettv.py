# coding: UTF-8
import ast
import base64
import hashlib
import sys, re
import xbmc, xbmcgui, xbmcplugin, xbmcvfs
import time
import requests
import routing
from datetime import datetime

from .helper import Helper

plugin = routing.Plugin()
base_url = plugin.base_url
handle = plugin.handle
helper = Helper(base_url=base_url, handle=handle)

# --- DEBUG BEÁLLÍTÁS ---
DEBUG = False  # True: logol, False: nem

def debug_log(msg):
    if DEBUG:
        xbmc.log(f'[SweetTV DEBUG] {msg}', level=xbmc.LOGDEBUG)

try:
    # Python 3
    from urllib.parse import quote_plus, unquote_plus, quote, unquote,parse_qsl,urlencode
    to_unicode = str
except:
    # Python 2.7
    from urllib import quote_plus, unquote_plus, quote, unquote,urlencode
    from urlparse import parse_qsl
    to_unicode = unicode

def getTime(x, y):
    if not x:
        return ''
    if y == 'date':
        fmt = '%Y-%m-%d'
    elif y == 'hour':
        fmt = '%H:%M'
    else:
        fmt = '%Y-%m-%d %H:%M'
    return datetime.fromtimestamp(int(x)).strftime(fmt)    
def channelList():
    xbmc.log("[SweetTV DEBUG] channelList indítása", xbmc.LOGINFO)

    # --- TOKEN BIZTOSÍTÁS (frissít, ha kell) ---
    if not helper.ensure_token():
        xbmc.log("[SweetTV] Token hiba channelList", xbmc.LOGERROR)
        return {}
    timestamp = int(time.time())
    json_data = {
        'epg_limit_prev': 1,
        'epg_limit_next': 72,
        'epg_current_time': timestamp,
        'need_epg': True,
        'need_list': True,
        'need_categories': True,
        'need_offsets': True,
        'need_hash': False,
        'need_icons': True,
        'need_big_icons': False,
    }

    url = helper.base_api_url.format('TvService/GetChannels.json')

    headers = {
        'Host': 'api.sweet.tv',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36',       
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'hu',
        'x-device': '1;22;0;2;' + helper.version,
        'origin': 'https://sweet.tv',
        'dnt': '1',
        'referer': 'https://sweet.tv/',    }

    xbmc.log("[SweetTV DEBUG] GetChannels kérés küldése", xbmc.LOGINFO)
    xbmc.log("[SweetTV DEBUG] Bearer hossz: %s" % len(helper.get_setting('bearer') or ""), xbmc.LOGINFO)

    jsdata = helper.request_sess(
        url,
        method='post',
        headers=headers,
        data=json_data,
        is_json=True,
        json_data=True
    )

    # --- TOKEN LEJÁRT (API jelzés) kezelése ---
    if not isinstance(jsdata, dict) or jsdata.get("status") != "OK":
        xbmc.log("[SweetTV] GetChannels API error", xbmc.LOGERROR)
        helper.notification("SweetTV", "Csatornalista betöltése sikertelen!")
        return {}    
    return jsdata

@plugin.route('/')
def root():
    CreateDatas()
	
    if helper.logged:
        startwt()

    else:
        helper.add_item('[COLOR lime][B]Belépés[/COLOR][/B]', plugin.url_for(login),folder=False)
        helper.add_item('[B]Beállítások[/B]', plugin.url_for(ustawienia),folder=False)

    helper.eod()

def CreateDatas():
    uuid_saved = helper.get_setting('uuid')
    if not uuid_saved:
        import uuid
        uuidx = uuid.uuid4()
        uuid_str = to_unicode(uuidx)
        helper.set_setting('uuid', uuid_str)  # mentés a beállításokba
        helper.uuid = uuid_str               # RAM-ban is tároljuk
    else:
        helper.uuid = uuid_saved             # ha van mentett UUID, azt használjuk
    return    
@plugin.route('/startwt')    
def startwt():
   
    helper.add_item('[B]TV[/B]', plugin.url_for(mainpage,id='live'),folder=True)
    helper.add_item('[B]Visszanézhető műsorok[/B]', plugin.url_for(mainpage,id='replay'),folder=True)
    helper.add_item('[B]Kijelentkezés[/B]', plugin.url_for(logout),folder=False)
@plugin.route('/getEPG/<id>')
def getEPG(id):

    id, dur = id.split('|')
    timestamp = int(time.time())

    json_data = {
        "channels": [int(id)],
        "epg_current_time": timestamp,
        "need_big_icons": False,
        "need_categories": False,
        "need_epg": True,
        "need_icons": False,
        "need_list": True,
        "need_offsets": False
    }

    url = 'https://api.sweet.tv/TvService/GetChannels.json'

    headers = {
        'Host': 'api.sweet.tv',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'hu',
        'x-device': '1;22;0;2;' + helper.version,
        'origin': 'https://sweet.tv',
        'dnt': '1',
        'referer': 'https://sweet.tv/'
    }

    jsdata = helper.request_sess(
        url,
        'post',
        headers=headers,
        data=json_data,
        is_json=True,
        json_data=True
    )

    if not isinstance(jsdata, dict):
        return

    if jsdata.get("status") == "OK":
        progs = jsdata['list'][0]['epg']
        now = int(time.time())

        for p in progs:
            tStart = p.get('time_start')

            if (
                p.get('available') and
                tStart and
                tStart >= now - int(dur) * 86400 and
                tStart <= now
            ):
                pid = str(p.get('id'))
                tit = p.get('text')
                date = getTime(tStart, 'date')
                ts = getTime(tStart, 'hour')
                te = getTime(p.get('time_stop'), 'hour')

                title = f'[COLOR=gold]{date}[/COLOR] | [B]{ts}-{te}[/B] {tit}'
                ID = id + '|' + pid

                helper.add_item(
                    title,
                    plugin.url_for(playvid, id=ID),
                    playable=True,
                    info={'title': title},
                    art={
                        'icon': p.get('preview_url'),
                        'fanart': helper.addon.getAddonInfo('fanart')
                    },
                    folder=False,
                    content='videos'
                )

    helper.eod()            
@plugin.route('/mainpage/<id>')    
def mainpage(id):
    jsdata=channelList()
    
    if jsdata.get("status", None) == 'OK':
        for j in jsdata.get('list', []):
            catchup = j.get('catchup',None)
            available = j.get('available',None)
            isShow=False
            if (id=='replay' and catchup and available) or (id=='live' and available):
                isShow=True
            if isShow==True:
                _id = str(j.get('id',None))
                title = j.get('name',None)
                slug = j.get('slug',None)
                epgs = j.get('epg',None)
                epg =''
                if id=='live' and epgs:
                    for e in epgs:
                        if e.get('time_stop',None)>int(time.time()):
                            tit=e.get('text',None)
                            ts=getTime(e.get('time_start',None),'hour')
                            te=getTime(e.get('time_stop',None),'hour')
                            epg+='[B]%s-%s[/B] %s\n'%(ts,te,tit)

                if id=='live':
                    idx = _id+'|null'#+slug
                    mod = plugin.url_for(playvid, id=idx)
                    fold = False
                    ispla = True
                elif id=='replay':
                    dur=str(j.get('catchup_duration',None))
                    idx = _id+'|'+dur
                    mod = plugin.url_for(getEPG, id=idx)
                    fold = True
                    ispla = False
                
                imag = j.get('icon_v2_url',None)
                art = {'icon': imag, 'fanart': helper.addon.getAddonInfo('fanart')}
                     
                info = {'title': title, 'plot':epg}
                
                helper.add_item('[COLOR gold][B]'+title+'[/COLOR][/B]', mod, playable=ispla, info=info, art=art, folder=fold)    

    helper.eod()
    
@plugin.route('/empty')    
def empty():
    return

@plugin.route('/ustawienia')
def ustawienia():
    helper.open_settings()
    helper.refresh()

@plugin.route('/logout')
def logout():
    log_out = helper.dialog_choice(
        'Figyelem',
        'Ki szeretne jelentkezni?',
        agree='IGEN',
        disagree='NEM'
    )

    if not log_out:
        return

    # --- Settings törlés ---
    helper.set_setting('bearer', '')
    helper.set_setting('refresh_token', '')
    helper.set_setting('token_time', '')
    helper.set_setting('expires_in', '')
    helper.set_setting('logged', 'false')

    # --- RAM változók nullázása ---
    helper.bearer = None
    helper.refresh_token = None

    # --- Session biztonságos reset ---
    if helper._sess:
        helper._sess.headers.pop("authorization", None)
        helper._sess.cookies.clear()

    # Ha teljesen tiszta session kell:
    # import requests
    # helper._sess = requests.Session()

    helper.refresh()
@plugin.route('/login')
def login():
    xbmc.log("===== [SweetTV DEBUG] Bejelentkezés indítása =====", xbmc.LOGINFO)

    # Helper login meghívása
    if helper.do_login():
        helper.refresh()
    else:
        helper.notification("SweetTV", "Bejelentkezés sikertelen!")

@plugin.route('/playvid/<id>')
def playvid(id):
    # --- Belépés ellenőrzés ---
    if str(helper.get_setting('logged')).lower() != 'true':
        xbmcgui.Dialog().notification('Sweet.tv', 'Jelentkezzen be a bővítménybe', xbmcgui.NOTIFICATION_INFO)
        xbmcplugin.setResolvedUrl(helper.handle, False, xbmcgui.ListItem())
        return

    # --- Token ellenőrzés ---
    if not helper.ensure_token():
        xbmcplugin.setResolvedUrl(helper.handle, False, xbmcgui.ListItem())
        return

    # --- ID feldolgozás ---
    if '|' in id:
        idx, pid = id.split('|', 1)
    else:
        idx, pid = id, 'null'

    json_data = {'without_auth': True, 'channel_id': int(idx), 'multistream': True}
    vod = False
    if pid != 'null':
        json_data['epg_id'] = int(pid)
        vod = True

    headers = {
        'Host': 'api.sweet.tv',
        'user-agent': helper.UA,
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'hu',
        'x-device': '1;22;0;2;' + helper.version,
        'origin': 'https://sweet.tv',
        'dnt': '1',
        'referer': 'https://sweet.tv/'
    }

    url = helper.base_api_url.format('TvService/OpenStream.json')
    jsdata = helper.request_sess(url, 'post', headers=headers, data=json_data, is_json=True, json_data=True)

    # --- Hibakezelés ---
    if not jsdata or jsdata.get("result") != 'OK':
        xbmcplugin.setResolvedUrl(helper.handle, False, xbmcgui.ListItem())
        return
    if jsdata.get("code") == 13:
        xbmcgui.Dialog().notification('Sweet.tv', 'A felvétel nem érhető el', xbmcgui.NOTIFICATION_INFO)
        xbmcplugin.setResolvedUrl(helper.handle, False, xbmcgui.ListItem())
        return

    host = jsdata.get('http_stream', {}).get('host', {}).get('address')
    nt = jsdata.get('http_stream', {}).get('url')
    if not host or not nt:
        xbmcplugin.setResolvedUrl(helper.handle, False, xbmcgui.ListItem())
        return

    stream_url = f'https://{host}{nt}'
    scheme = jsdata.get('scheme')
    DRM = None
    lic_url = None
    subs = None

    # --- DASH / Widevine ---
    if scheme == 'HTTP_DASH':
        PROTOCOL = 'mpd'
        if jsdata.get('drm_type') == 'DRM_WIDEVINE':
            licURL = jsdata.get('license_server')
            hea_lic = {'User-Agent': helper.UA, 'origin': 'https://sweet.tv', 'referer': 'https://sweet.tv/'}
            from urllib.parse import urlencode
            lic_url = f"{licURL}|{urlencode(hea_lic)}|R{{SSM}}|"
            DRM = 'com.widevine.alpha'
    # --- HLS ---
    elif scheme == 'HTTP_HLS':
        PROTOCOL = 'hls'
    else:
        xbmcplugin.setResolvedUrl(helper.handle, False, xbmcgui.ListItem())
        return

    # --- Lejátszó kiválasztás ---
    if helper.get_setting('playerType') == 'ffmpeg' and DRM is None:
        helper.ffmpeg_player(stream_url)
    else:
        helper.PlayVid(stream_url, lic_url, PROTOCOL, DRM, flags=False, subs=subs, vod=vod)
@plugin.route('/listM3U')
def listM3U():
    import os
    import re
    import time
    import xbmcgui
    import xbmcvfs

    try:
        from urllib.request import urlopen
    except ImportError:
        from urllib2 import urlopen

    epg_url = "https://epgshare01.online/epgshare01/epg_ripper_HU1.xml.gz"
    epg_txt_url = "https://epgshare01.online/epgshare01/epg_ripper_HU1.txt"

    if str(helper.get_setting('logged')).lower() != 'true':
        xbmcgui.Dialog().notification('Sweet.tv', 'Jelentkezzen be a bővítménybe', xbmcgui.NOTIFICATION_INFO)
        return

    if not helper.ensure_token():
        xbmcgui.Dialog().notification('Sweet.tv', 'Token hiba', xbmcgui.NOTIFICATION_ERROR)
        return

    file_name = helper.get_setting('fname')
    path_m3u = helper.get_setting('path_m3u')
    if not file_name or not path_m3u:
        xbmcgui.Dialog().notification('Sweet.tv', 'Adja meg a fájlnevet és a célkönyvtárat.', xbmcgui.NOTIFICATION_ERROR)
        return

    cache_file = xbmcvfs.translatePath(os.path.join(path_m3u, "hu1_ids_cache.txt"))
    HU1_IDS = set()
    now = time.time()
    cache_valid = False

    if xbmcvfs.exists(cache_file):
        try:
            stat = xbmcvfs.Stat(cache_file)
            modified = stat.st_mtime()
            if modified and (now - modified < 86400):
                cache_valid = True
        except:
            cache_valid = False

    def load_ids_from_text(txt):
        for line in txt.splitlines():
            line = line.strip()
            if line:
                HU1_IDS.add(line)

    if cache_valid:
        try:
            f = xbmcvfs.File(cache_file)
            content = f.read()
            f.close()
            load_ids_from_text(content)
        except:
            cache_valid = False

    if not cache_valid:
        try:
            response = urlopen(epg_txt_url)
            raw = response.read()
            txt = raw.decode("utf-8", errors="ignore")
            f = xbmcvfs.File(cache_file, "w")
            f.write(txt)
            f.close()
            load_ids_from_text(txt)
        except Exception:
            xbmcgui.Dialog().notification('Sweet.tv', 'HU1 TXT letöltési hiba - cache fallback', xbmcgui.NOTIFICATION_WARNING)
            if xbmcvfs.exists(cache_file):
                try:
                    f = xbmcvfs.File(cache_file)
                    content = f.read()
                    f.close()
                    load_ids_from_text(content)
                except:
                    pass

    data = '#EXTM3U x-tvg-url="{}"\n'.format(epg_url)
    channels = channelList()
    if not channels or 'list' not in channels or not channels['list']:
        xbmcgui.Dialog().notification('Sweet.tv', 'Nem érkezett csatornalista', xbmcgui.NOTIFICATION_ERROR)
        return

    for c in channels['list']:
        if not c.get('available'):
            continue

        sweet_id = str(c.get('id', '')).strip()
        cName = str(c.get('name', '')).strip()
        img = str(c.get('icon_v2_url', '')).strip()

        if not sweet_id or not cName:
            continue

        # Ha a TXT-ben van hozzá id, azt használja a tvg-id-hez, különben a SweetTV id
        tvg_id = cName + ".hu" if (cName + ".hu") in HU1_IDS else sweet_id

        stream_url = "plugin://plugin.video.sweettvhu/playvid/{}|null".format(sweet_id)

        data += '#EXTINF:-1 tvg-id="{0}" tvg-name="{1}" tvg-logo="{2}" group-title="Sweet.tv",{1}\n'.format(tvg_id, cName, img)
        data += stream_url + "\n"

    try:
        if not xbmcvfs.exists(path_m3u):
            xbmcvfs.mkdirs(path_m3u)

        full_path = xbmcvfs.translatePath(os.path.join(path_m3u, file_name))
        f = xbmcvfs.File(full_path, 'w')
        f.write(data)
        f.close()

        xbmcgui.Dialog().notification('Sweet.tv', 'M3U lista létrehozva', xbmcgui.NOTIFICATION_INFO)
    except Exception as e:
        xbmcgui.Dialog().notification('Sweet.tv', 'Mentési hiba: {}'.format(str(e)), xbmcgui.NOTIFICATION_ERROR)
class SweetTV(Helper):
    def __init__(self):
        super().__init__()
        plugin.run()
