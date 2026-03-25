import asyncio, json, ssl, time, threading
import aiohttp, urllib3
from flask import Flask, request, jsonify
from datetime import datetime
from protobuf_decoder.protobuf_decoder import Parser
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
_ID  = '4665582275'
_PW  = 'FPISX74WUE'
_TTL = 6 * 60 * 60
_cx  = {}
_lk  = threading.Lock()

_Hr = {
    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Expect': '100-continue',
    'X-Unity-Version': '2018.4.11f1',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB52',
}

def _rdVr(data, pos):
    n = 0; sh = 0
    while True:
        b = data[pos]; pos += 1
        n |= (b & 0x7F) << sh; sh += 7
        if not b & 0x80: break
    return n, pos

def _pbF(data):
    out = {}; pos = 0
    while pos < len(data):
        try:
            tag, pos = _rdVr(data, pos)
            fn = tag >> 3; wt = tag & 0x7
            if wt == 0:
                v, pos = _rdVr(data, pos); out[fn] = v
            elif wt == 2:
                ln, pos = _rdVr(data, pos); out[fn] = data[pos:pos+ln]; pos += ln
            elif wt == 1:
                out[fn] = data[pos:pos+8]; pos += 8
            elif wt == 5:
                out[fn] = data[pos:pos+4]; pos += 4
            else: break
        except: break
    return out

async def _vr(n):
    h = []
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        h.append(b)
        if not n: break
    return bytes(h)

async def _enc(hx, k, v):
    return AES.new(k, AES.MODE_CBC, v).encrypt(pad(bytes.fromhex(hx), 16)).hex()

async def _hx(n):
    f = hex(n)[2:]
    return ('0' + f) if len(f) == 1 else f

async def _var(fn, val):
    return await _vr((fn << 3) | 0) + await _vr(val)

async def _len(fn, val):
    e = val.encode() if isinstance(val, str) else val
    return await _vr((fn << 3) | 2) + await _vr(len(e)) + e

async def _pb(flds):
    p = bytearray()
    for f, v in flds.items():
        if isinstance(v, dict): p.extend(await _len(f, await _pb(v)))
        elif isinstance(v, int): p.extend(await _var(f, v))
        elif isinstance(v, (str, bytes)): p.extend(await _len(f, v))
    return p

async def _pk(px, n, k, v):
    e = await _enc(px, k, v)
    _ = await _hx(len(e) // 2)
    m = {2:'000000', 3:'00000', 4:'0000', 5:'000'}
    return bytes.fromhex(n + m.get(len(_), '000000') + _ + e)

async def _fix(rs):
    d = {}
    for r in rs:
        fd = {'wire_type': r.wire_type}
        if r.wire_type in ('varint', 'string', 'bytes'): fd['data'] = r.data
        elif r.wire_type == 'length_delimited': fd['data'] = await _fix(r.data.results)
        d[r.field] = fd
    return d

async def _parse(hx):
    try: return json.dumps(await _fix(Parser().parse(hx)))
    except: return None

async def _uidEnc(uid):
    return (await _pb({1: int(uid)})).hex()[2:]

async def _stPkt(uid, k, v):
    ue = await _uidEnc(int(uid))
    return await _pk(f"080112090A05{ue}1005", '0F15', k, v)

async def _rmPkt(ruid, k, v):
    return await _pk((await _pb({1: 1, 2: {1: ruid, 3: {}, 4: 1, 6: 'en'}})).hex(), '0E15', k, v)

def _tdiff(ts):
    d = int((datetime.now() - datetime.fromtimestamp(ts)).total_seconds())
    return f"{(abs(d) % 3600) // 60:02}:{abs(d) % 60:02}"

def _pStatus(pkt):
    data = json.loads(pkt)
    if '5' not in data or 'data' not in data['5']: return {'status': 'OFFLINE'}
    jd = data['5']['data']
    if '1' not in jd or 'data' not in jd['1']: return {'status': 'OFFLINE'}
    d = jd['1']['data']
    if '3' not in d or 'data' not in d['3']: return {'status': 'OFFLINE'}
    st = d['3']['data']
    gc = d.get('9', {}).get('data', 0)
    cm = d.get('10', {}).get('data', 0) + 1 if '10' in d else 0
    go = d.get('8', {}).get('data', 0)
    tg = d.get('4', {}).get('data', 0)
    m5 = d.get('5', {}).get('data')
    m6 = d.get('6', {}).get('data')
    mn = sc = 0
    if tg:
        a, b = _tdiff(tg).split(':'); mn = int(a); sc = int(b)
    if st == 4:
        return {'status': 'IN_ROOM', 'room_uid': d.get('15', {}).get('data'),
                'players': f"{d.get('17',{}).get('data',0)}/{d.get('18',{}).get('data',0)}",
                'room_owner': d.get('1', {}).get('data')}
    base = {1:'SOLO', 2:'INSQUAD', 3:'INGAME', 5:'INGAME', 7:'MATCHMAKING', 6:'SOCIAL_ISLAND'}.get(st, 'OFFLINE')
    mode = None
    f14 = d.get('14', {}).get('data')
    if f14 == 1: mode = 'TRAINING'
    elif f14 == 2: mode = 'SOCIAL_ISLAND'
    mm = {(2,1):'BR_RANK',(5,23):'TRAINING',(6,15):'CS_RANK',(1,43):'LONE_WOLF',
          (1,1):'BERMUDA',(1,15):'CLASH_SQUAD',(1,29):'CONVOY_CRUNCH',(1,61):'FREE_FOR_ALL'}
    if (m5, m6) in mm: mode = mm[(m5, m6)]
    res = {'status': base, 'mode': mode}
    if base == 'INSQUAD':
        res['squad_owner'] = go
        res['squad_size'] = f"{gc}/{cm}" if gc else None
    if base in ('INGAME', 'INSQUAD') and tg:
        res['time_playing'] = f"{mn}m {sc}s"
    return res

def _pRoom(pkt):
    data = json.loads(pkt)
    rd = data['5']['data']['1']['data']
    mm = {1:'BERMUDA',201:'BATTLE_CAGE',15:'CLASH_SQUAD',43:'LONE_WOLF',3:'RUSH_HOUR',27:'BOMB_SQUAD_5V5',24:'DEATH_MATCH'}
    return {
        'room_id': int(rd['1']['data']),
        'room_name': rd['2']['data'],
        'owner_uid': int(rd['37']['data']['1']['data']),
        'mode': mm.get(rd.get('4', {}).get('data'), 'UNKNOWN'),
        'players': f"{rd.get('6',{}).get('data',0)}/{rd.get('7',{}).get('data',0)}",
        'spectators': rd.get('9', {}).get('data', 0),
        'emulator': bool(rd.get('17', {}).get('data', 1)),
    }

async def _rAll(reader, timeout=5):
    buf = b''
    while True:
        try: chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        except asyncio.TimeoutError: break
        if not chunk: break
        buf += chunk
    return buf

async def _scan(buf, k, v):
    h = buf.hex()
    for mk, pt in [('0f00','0f'),('0e00','0e')]:
        i = h.find(mk)
        if i != -1 and i % 2 == 0: return pt, h[i + 10:]
    if len(buf) > 5:
        pl = buf[5:]; pl = pl[:len(pl) - (len(pl) % 16)]
        if len(pl) >= 16:
            try:
                dc = unpad(AES.new(k, AES.MODE_CBC, v).decrypt(pl), 16).hex()
                for mk, pt in [('0f00','0f'),('0e00','0e')]:
                    i = dc.find(mk)
                    if i != -1 and i % 2 == 0: return pt, dc[i + 10:]
            except: pass
    return None, None

async def _mkLogin(oid, atk):
    return await _pb({
        3: str(datetime.now())[:-7], 4: 'free fire', 5: 1, 7: '1.120.1',
        8: 'Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)',
        9: 'Handheld', 10: 'Verizon', 11: 'WIFI', 12: 1920, 13: 1080,
        14: '280', 15: 'ARM64 FP ASIMD AES VMH | 2865 | 4', 16: 3003,
        17: 'Adreno (TM) 640', 18: 'OpenGL ES 3.1 v1.46',
        19: 'Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57',
        20: '223.191.51.89', 21: 'en', 22: oid, 23: '4', 24: 'Handheld',
        25: {6: 55, 8: 81},
        29: atk, 30: 1, 73: 3, 78: 3, 79: 2, 81: '64',
        93: 'android', 97: 1, 98: 1, 99: '4', 100: '4',
    })

async def _auth(uid, tok, ts, k, v):
    uh = hex(uid)[2:]
    hd = {9:'0000000',8:'00000000',10:'000000',7:'000000000'}.get(len(uh),'0000000')
    e = await _enc(tok.encode().hex(), k, v)
    el = await _hx(len(e) // 2)
    return f"0115{hd}{uh}{await _hx(ts)}00000{el}{e}"

async def _login():
    sx = ssl.create_default_context()
    sx.check_hostname = False; sx.verify_mode = ssl.CERT_NONE

    async with aiohttp.ClientSession() as s:
        async with s.post('https://100067.connect.garena.com/oauth/guest/token/grant', headers=_Hr,
            data={'uid':_ID,'password':_PW,'response_type':'token','client_type':'2',
                  'client_secret':'2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3',
                  'client_id':'100067'}, ssl=sx) as r:
            if r.status != 200: raise Exception(f"OAuth {r.status}")
            d = await r.json()
            oid = d['open_id']; atk = d['access_token']

    raw = await _mkLogin(oid, atk)
    ep  = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%').encrypt(pad(raw, 16))

    async with aiohttp.ClientSession() as s:
        async with s.post('https://loginbp.ggpolarbear.com/MajorLogin', data=ep, headers=_Hr, ssl=sx) as r:
            if r.status != 200: raise Exception(f"MajorLogin {r.status}")
            mr = await r.read()

    mlr = _pbF(mr)
    tok = mlr[8].decode()
    tgt = mlr[1]
    k   = mlr[22]
    v   = mlr[23]
    ts  = mlr[21]
    url = mlr[10].decode()

    h2 = {**_Hr, 'Authorization': f'Bearer {tok}'}
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{url}/GetLoginData", data=ep, headers=h2, ssl=sx) as r:
            if r.status != 200: raise Exception(f"GetLoginData {r.status}")
            lr = await r.read()

    ld = _pbF(lr)
    ip, port = ld[14].decode().split(':')
    at = await _auth(int(tgt), tok, int(ts), k, v)
    print(f"\n ACCOUNT ID --> {tgt}\n JWT TOKEN: {tok[:50]}...\n BOT ON\n")
    return {'account_id':tgt,'token':tok,'key':k,'iv':v,'ip':ip,'port':int(port),'auth':at,'exp':time.time()+_TTL}

def _sess():
    with _lk:
        s = _cx.get('s')
        if s and time.time() < s['exp']: return s
    ns = asyncio.run(_login())
    with _lk: _cx['s'] = ns
    return ns

async def _query(uid, sx):
    rd, wr = await asyncio.open_connection(sx['ip'], sx['port'])
    try:
        wr.write(bytes.fromhex(sx['auth'])); await wr.drain()
        await _rAll(rd, timeout=3)
        pkt = await _stPkt(uid, sx['key'], sx['iv'])
        wr.write(pkt); await wr.drain()
        buf = await _rAll(rd, timeout=5)
        if not buf: return {'status': 'NO_RESPONSE'}
        pt, pl = await _scan(buf, sx['key'], sx['iv'])
        if pt == '0f':
            raw = await _parse(pl)
            if not raw: return {'status': 'PARSE_ERROR'}
            info = _pStatus(raw)
            if info.get('status') == 'IN_ROOM':
                wr.write(await _rmPkt(int(info['room_uid']), sx['key'], sx['iv'])); await wr.drain()
                rb = await _rAll(rd, timeout=5)
                if rb:
                    rt, rp = await _scan(rb, sx['key'], sx['iv'])
                    if rt == '0e':
                        rr = await _parse(rp)
                        if rr: info['room_info'] = _pRoom(rr)
            return info
        elif pt == '0e':
            raw = await _parse(pl)
            return _pRoom(raw) if raw else {'status': 'PARSE_ERROR'}
        return {'status': 'UNKNOWN', 'buf': buf.hex()[:120]}
    finally:
        wr.close()
        try: await wr.wait_closed()
        except: pass

@app.route('/health')
def health():
    return jsonify({'status': 'ok'}), 200

@app.route('/s')
def route_s():
    uid = request.args.get('uid', '').strip()
    if not uid or not uid.isdigit(): return jsonify({'error': 'uid required'}), 400
    try:
        sx = _sess()
        return jsonify({'uid': uid, **asyncio.run(_query(uid, sx))})
    except Exception as e:
        import traceback; traceback.print_exc()
        with _lk: _cx.clear()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
