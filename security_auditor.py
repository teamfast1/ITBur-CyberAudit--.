#!/usr/bin/env python3
"""
Security Auditor — Web GUI
Запуск: sudo python3 security_auditor.py
"""

import os, re, stat, subprocess, json, threading, webbrowser

try:
    from flask import Flask, jsonify, request, Response
except ImportError:
    print("[!] pip3 install flask")
    raise SystemExit(1)

app = Flask(__name__)

# Категории флагов — для них не будет кнопки "Применить"
FLAG_CATEGORIES = {"Поиск флагов (имя)", "Поиск флагов (содержимое)", "Поиск флагов (grep)"}


class SecurityAuditor:
    def __init__(self):
        self.report = []

    def add(self, cat, threat, fix, line="", path=""):
        self.report.append({"category": cat, "threat": threat, "recommendation": fix,
                            "line_content": line, "filepath": path})

    def audit_file_permissions(self):
        for d in ['/etc', '/var', '/home']:
            if not os.path.exists(d): continue
            for root, dirs, files in os.walk(d):
                for name in files:
                    fp = os.path.join(root, name)
                    try:
                        m = os.stat(fp).st_mode
                        if all(bool(m & f) for f in [stat.S_IWOTH, stat.S_IROTH, stat.S_IXOTH]):
                            self.add("Анализ прав доступа", f"Файл 777: {fp}", f"sudo chmod 644 {fp}", path=fp)
                        if "shadow" in name and bool(m & stat.S_IROTH):
                            self.add("Утечка данных", f"Shadow доступен: {fp}",
                                     f"sudo chmod 640 {fp} && sudo chown root:shadow {fp}", path=fp)
                    except (PermissionError, FileNotFoundError, OSError):
                        pass

    def audit_network(self):
        try:
            out = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True, timeout=30).stdout
            dangerous = {"21": "FTP", "23": "Telnet", "25": "SMTP", "3306": "MySQL", "5432": "PostgreSQL"}
            for line in out.split('\n'):
                for port, desc in dangerous.items():
                    if f":{port} " in line:
                        proc = ""
                        m = re.search(r'users:\(\("([^"]+)"', line)
                        if m: proc = m.group(1)
                        fix = f"sudo fuser -k {port}/tcp && sudo systemctl stop {proc or desc.lower()} 2>/dev/null; sudo systemctl disable {proc or desc.lower()} 2>/dev/null && sudo iptables -A INPUT -p tcp --dport {port} -j DROP"
                        self.add("Сетевой аудит", f"Открыт порт {port} ({desc}){' — процесс: '+proc if proc else ''}", fix)
        except Exception: pass

    def audit_services(self):
        try:
            out = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager'],
                                 capture_output=True, text=True, timeout=30).stdout
            for svc, desc in {"telnet": "Telnet", "vsftpd": "FTP", "rsh": "RSH"}.items():
                if svc in out:
                    self.add("Опасные сервисы", f"Запущен: {svc} ({desc})",
                             f"sudo systemctl stop {svc} && sudo systemctl disable {svc}")
        except Exception: pass

    def audit_users(self):
        try:
            for line in open('/etc/passwd'):
                p = line.strip().split(':')
                if len(p) >= 4 and p[2] == '0' and p[0] != 'root':
                    self.add("Аудит пользователей", f"{p[0]} имеет UID 0", f"sudo userdel {p[0]}")
        except Exception: pass
        try:
            out = subprocess.run(['awk', '-F:', '($2 == "" ) {print $1}', '/etc/shadow'],
                                 capture_output=True, text=True, timeout=10).stdout
            for u in out.strip().split('\n'):
                if u: self.add("Аудит пользователей", f"Без пароля: {u}", f"sudo passwd {u}")
        except Exception: pass

    def audit_packages(self):
        """Аудит установленных пакетов — проверка устаревших версий и известных уязвимых пакетов."""
        # Известные уязвимые пакеты/версии (упрощённая локальная база)
        known_vulnerable = {
            "openssl": {"below": "3.0", "cve": "CVE-2022-3602", "desc": "Критическая уязвимость в OpenSSL < 3.0"},
            "apache2": {"below": "2.4.54", "cve": "CVE-2022-31813", "desc": "Обход аутентификации в Apache < 2.4.54"},
            "nginx": {"below": "1.22", "cve": "CVE-2022-41741", "desc": "Переполнение буфера в nginx < 1.22"},
            "openssh-server": {"below": "9.0", "cve": "CVE-2023-38408", "desc": "Удалённое выполнение кода в OpenSSH < 9.0"},
            "mysql-server": {"below": "8.0.32", "cve": "CVE-2023-21977", "desc": "SQL-инъекция в MySQL < 8.0.32"},
            "curl": {"below": "7.87", "cve": "CVE-2023-23914", "desc": "Утечка данных через HSTS в curl < 7.87"},
            "sudo": {"below": "1.9.13", "cve": "CVE-2023-22809", "desc": "Обход sudoedit в sudo < 1.9.13"},
            "bash": {"below": "5.2", "cve": "CVE-2022-3715", "desc": "Переполнение кучи в bash < 5.2"},
            "php": {"below": "8.1", "cve": "CVE-2023-3247", "desc": "Множественные уязвимости в PHP < 8.1"},
            "postgresql": {"below": "15.2", "cve": "CVE-2023-2454", "desc": "Обход привилегий в PostgreSQL < 15.2"},
        }

        installed = {}

        # Попробовать dpkg (Debian/Ubuntu)
        try:
            r = subprocess.run(['dpkg-query', '-W', '-f', '${Package}\t${Version}\n'],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                for line in r.stdout.strip().split('\n'):
                    parts = line.split('\t', 1)
                    if len(parts) == 2:
                        installed[parts[0]] = parts[1]
        except Exception: pass

        # Попробовать rpm (RHEL/CentOS/Fedora)
        if not installed:
            try:
                r = subprocess.run(['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}\n'],
                                   capture_output=True, text=True, timeout=30)
                if r.returncode == 0:
                    for line in r.stdout.strip().split('\n'):
                        parts = line.split('\t', 1)
                        if len(parts) == 2:
                            installed[parts[0]] = parts[1]
            except Exception: pass

        if not installed:
            self.add("Аудит пакетов", "Не удалось получить список пакетов (dpkg/rpm не найден)",
                     "apt list --installed  # или rpm -qa")
            return

        self.add("Аудит пакетов",
                 f"Всего установлено пакетов: {len(installed)}",
                 "dpkg-query -W -f '${Package}\\t${Version}\\n' | sort")

        # Проверка по локальной базе
        for pkg, info in known_vulnerable.items():
            if pkg in installed:
                ver = installed[pkg]
                # Простое сравнение — берём первую числовую часть версии
                try:
                    ver_clean = re.match(r'[\d.]+', ver)
                    below_clean = re.match(r'[\d.]+', info['below'])
                    if ver_clean and below_clean:
                        v_parts = [int(x) for x in ver_clean.group().split('.')]
                        b_parts = [int(x) for x in below_clean.group().split('.')]
                        # Pad to same length
                        while len(v_parts) < len(b_parts): v_parts.append(0)
                        while len(b_parts) < len(v_parts): b_parts.append(0)
                        if v_parts < b_parts:
                            self.add("Аудит пакетов",
                                     f"{pkg} v{ver} — {info['desc']} ({info['cve']})",
                                     f"sudo apt update && sudo apt upgrade {pkg}  # или yum update {pkg}")
                except Exception:
                    pass

        # Проверка на пакеты с доступными обновлениями безопасности
        try:
            r = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                upgradable = [l for l in r.stdout.strip().split('\n') if l and 'Listing' not in l]
                if upgradable:
                    self.add("Аудит пакетов",
                             f"Доступно обновление для {len(upgradable)} пакетов",
                             "sudo apt update && sudo apt upgrade -y")
                    # Показать первые 10
                    for pkg_line in upgradable[:10]:
                        name = pkg_line.split('/')[0] if '/' in pkg_line else pkg_line
                        self.add("Аудит пакетов", f"Обновление: {pkg_line.strip()[:100]}",
                                 f"sudo apt install --only-upgrade {name}")
        except Exception: pass

    def audit_flag_search(self):
        keywords = ['bit26']
        pat = re.compile('|'.join(re.escape(k) for k in keywords), re.IGNORECASE)
        text_ext = {'.txt','.html','.htm','.xml','.json','.cfg','.conf','.log','.sh','.py',
                    '.env','.ini','.csv','.md','.yml','.yaml','.toml','.php','.js','.css','.sql','.bak','.config'}
        dirs = ['/etc', '/var', '/home', '/tmp', '/opt', '/root', '/srv', '/usr/local']
        found = set()
        for sd in dirs:
            if not os.path.exists(sd): continue
            for root, ds, files in os.walk(sd):
                ds[:] = [d for d in ds if not d.startswith('.')]
                for name in files:
                    fp = os.path.join(root, name)
                    if fp in found: continue
                    if pat.search(name):
                        found.add(fp)
                        ln = ""
                        try:
                            for l in open(fp, 'r', errors='ignore'):
                                if pat.search(l): ln = l.strip()[:200]; break
                        except Exception: pass
                        self.add("Поиск флагов (имя)", f"Файл: {fp}", f"cat {fp}", line=ln or name, path=fp)
                    _, ext = os.path.splitext(name)
                    if ext.lower() in text_ext:
                        try:
                            if os.path.getsize(fp) > 2*1024*1024: continue
                            for i, l in enumerate(open(fp, 'r', errors='ignore'), 1):
                                if pat.search(l):
                                    self.add("Поиск флагов (содержимое)", f"{fp} (стр.{i})",
                                             f"cat -n {fp} | head -n {i+5} | tail -n 10",
                                             line=l.strip()[:200], path=fp)
                                    found.add(fp); break
                        except Exception: pass
        try:
            for kw in keywords:
                for sd in dirs:
                    if not os.path.exists(sd): continue
                    r = subprocess.run(['grep','-rnI','-m','1','-i',kw,sd], capture_output=True, text=True, timeout=30)
                    for gl in r.stdout.strip().split('\n'):
                        if not gl.strip(): continue
                        parts = gl.split(':', 2)
                        fp = parts[0]
                        content = parts[2].strip()[:200] if len(parts) >= 3 else gl
                        if fp and fp not in found:
                            found.add(fp)
                            self.add("Поиск флагов (grep)", f"grep: {fp}", f"grep -in '{kw}' {fp}",
                                     line=content, path=fp)
        except Exception: pass

    def run_all(self):
        self.report = []
        self.audit_file_permissions()
        self.audit_network()
        self.audit_services()
        self.audit_users()
        self.audit_packages()
        self.audit_flag_search()
        return self.report


# ── Routes ──

@app.route('/')
def index():
    return Response(HTML, mimetype='text/html')

@app.route('/api/scan')
def api_scan():
    a = SecurityAuditor()
    findings = a.run_all()
    grouped = {}
    for f in findings:
        grouped.setdefault(f['category'], []).append(f)
    return jsonify({"total": len(findings), "categories": len(grouped), "grouped": grouped,
                    "flag_categories": list(FLAG_CATEGORIES)})

@app.route('/api/fix', methods=['POST'])
def api_fix():
    cmd = request.get_json(force=True).get('command', '')
    if not cmd: return jsonify({"ok": False, "error": "empty"}), 400
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return jsonify({"ok": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/fix-all', methods=['POST'])
def api_fix_all():
    cmds = request.get_json(force=True).get('commands', [])
    results = []
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            results.append({"cmd": cmd, "ok": r.returncode == 0, "err": r.stderr.strip()})
        except Exception as e:
            results.append({"cmd": cmd, "ok": False, "err": str(e)})
    ok_count = sum(1 for r in results if r['ok'])
    return jsonify({"ok": True, "total": len(cmds), "success": ok_count, "results": results})


# ── HTML ──

HTML = r'''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Auditor</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#111;color:#ccc;min-height:100vh;font-size:14px;line-height:1.5}
.app{max-width:880px;margin:0 auto;padding:2rem 1.2rem 5rem}
.header{text-align:center;margin-bottom:2rem;border-bottom:1px solid #333;padding-bottom:1.2rem}
.header h1{font-size:1.4rem;color:#fff}
.header p{color:#666;font-size:.8rem;margin-top:.2rem}

.scan-btn{
  display:flex;align-items:center;justify-content:center;gap:.5rem;
  width:260px;margin:0 auto 1.5rem;padding:.6rem 1rem;
  border:1px solid #444;border-radius:3px;background:#1a1a1a;color:#fff;
  font-family:monospace;font-size:.85rem;cursor:pointer}
.scan-btn:hover{background:#252525}
.scan-btn:disabled{opacity:.4;cursor:default}
.scan-btn .sp{width:14px;height:14px;border:2px solid #444;border-top-color:#fff;border-radius:50%;animation:s .5s linear infinite;display:none}
.scan-btn.ld .sp{display:block}
.scan-btn.ld .bl{display:none}
@keyframes s{to{transform:rotate(360deg)}}

.stats{display:flex;gap:.5rem;margin-bottom:1.2rem}
.sc{flex:1;padding:.5rem;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:3px;text-align:center}
.sc .n{font-size:1.3rem;font-weight:700;color:#fff}
.sc .l{font-size:.65rem;color:#666;text-transform:uppercase}

.cat{margin-bottom:.5rem}
.ch{display:flex;align-items:center;gap:.5rem;padding:.5rem .7rem;cursor:pointer;
  background:#1a1a1a;border:1px solid #2a2a2a;border-radius:3px;user-select:none}
.ch:hover{background:#202020}
.ch .ar{color:#555;font-size:.65rem;transition:transform .15s}
.cat.o .ch .ar{transform:rotate(90deg)}
.ch .cn{font-weight:700;font-size:.8rem;flex:1;color:#ddd}
.ch .cc{background:#2a2a2a;color:#888;font-size:.65rem;font-weight:600;padding:.1rem .4rem;border-radius:2px}
.ch .fix-all-btn{padding:.2rem .5rem;border:1px solid #444;border-radius:2px;background:#1a1a1a;
  color:#aaa;font-family:monospace;font-size:.65rem;cursor:pointer}
.ch .fix-all-btn:hover{background:#2a2a2a;color:#fff}
.cb{max-height:0;overflow:hidden;transition:max-height .25s ease}
.cat.o .cb{max-height:99999px}

.fi{margin:.3rem 0 0;padding:.6rem .7rem;background:#141414;border:1px solid #222;border-radius:3px}
.fi .th{font-size:.78rem;color:#aaa;margin-bottom:.3rem}
.lc{font-family:monospace;font-size:.72rem;background:#0a0a0a;color:#777;padding:.4rem .5rem;
  border:1px solid #1a1a1a;border-radius:2px;margin-bottom:.4rem;white-space:pre-wrap;word-break:break-all;max-height:80px;overflow-y:auto}
.fb{display:flex;align-items:stretch;gap:.3rem;flex-wrap:wrap}
.fc{flex:1;min-width:0;font-family:monospace;font-size:.7rem;background:#0a0a0a;color:#666;
  padding:.35rem .5rem;border-radius:2px;border:1px solid #1a1a1a;white-space:pre-wrap;word-break:break-all}
.fa{display:flex;gap:.25rem;flex-wrap:wrap;align-items:center}
.fa button{padding:.25rem .5rem;border:1px solid #333;border-radius:2px;background:#1a1a1a;color:#999;
  font-family:monospace;font-size:.65rem;cursor:pointer}
.fa button:hover{background:#252525;color:#fff}
.fa button:disabled{opacity:.3;cursor:default}

.status{text-align:center;margin-bottom:1rem;font-size:.8rem;color:#666;display:none}
.empty{text-align:center;padding:2rem;color:#555;font-size:.8rem}
.toast{position:fixed;bottom:1.2rem;right:1.2rem;padding:.5rem .8rem;border-radius:3px;
  font-size:.75rem;font-weight:600;color:#fff;background:#222;border:1px solid #444;
  transform:translateY(120%);opacity:0;transition:all .2s;z-index:99}
.toast.show{transform:translateY(0);opacity:1}
.toast.err{border-color:#633;background:#2a1a1a}

@media(max-width:600px){.stats{flex-direction:column}.fb{flex-direction:column}}
</style>
</head>
<body>
<div class="app">
  <header class="header">
    <h1>Security Auditor</h1>
    <p>Аудит безопасности Linux</p>
  </header>
  <button class="scan-btn" id="sb" onclick="scan()">
    <span class="sp"></span><span class="bl">Сканировать</span>
  </button>
  <div class="status" id="st"></div>
  <div class="stats" id="sb2" style="display:none">
    <div class="sc"><div class="n" id="tc">0</div><div class="l">Проблем</div></div>
    <div class="sc"><div class="n" id="cc">0</div><div class="l">Категорий</div></div>
  </div>
  <div id="res"></div>
</div>
<div class="toast" id="toast"></div>
<script>
var catCmds={};
function toast(m,ok){const t=document.getElementById('toast');t.textContent=m;
  t.className='toast show'+(ok?'':' err');setTimeout(()=>t.className='toast',2500)}

async function scan(){
  const b=document.getElementById('sb'),r=document.getElementById('res'),
    s=document.getElementById('sb2'),st=document.getElementById('st');
  b.classList.add('ld');b.disabled=true;r.innerHTML='';s.style.display='none';
  st.style.display='block';st.textContent='Сканирование...';
  catCmds={};
  try{
    const d=await(await fetch('/api/scan')).json();
    const flagCats=new Set(d.flag_categories||[]);
    b.classList.remove('ld');b.disabled=false;
    if(!d.total){st.textContent='Проблем не найдено';st.style.color='#6a6';
      r.innerHTML='<div class="empty">OK</div>';return}
    st.textContent='Найдено: '+d.total;st.style.color='#aaa';
    document.getElementById('tc').textContent=d.total;
    document.getElementById('cc').textContent=d.categories;
    s.style.display='flex';
    const cats=Object.entries(d.grouped);
    let h='';
    cats.forEach(([cat,fds],ci)=>{
      const op=ci===0?' o':'';
      const isFlag=flagCats.has(cat);
      // Store commands in global object by index
      const nonSudoCmds=fds.map(f=>f.recommendation).filter(c=>!c.includes('sudo'));
      catCmds[ci]=nonSudoCmds;
      // Show "Fix All" only if there are non-sudo commands and it's not a flag category
      const fixAllBtn=(isFlag||!nonSudoCmds.length)?'':`<button class="fix-all-btn" onclick="event.stopPropagation();fixAll(this,${ci})">Исправить все (${nonSudoCmds.length})</button>`;
      h+=`<div class="cat${op}">
        <div class="ch" onclick="this.parentElement.classList.toggle('o')">
          <span class="ar">&#9654;</span><span class="cn">${esc(cat)}</span>
          ${fixAllBtn}
          <span class="cc">${fds.length}</span>
        </div><div class="cb">`;
      fds.forEach((f,fi)=>{
        const id=`f${ci}_${fi}`;
        let lh=f.line_content?`<div class="lc">${esc(f.line_content)}</div>`:'';
        let btns=`<button onclick="cp('${id}')">Копировать</button>`;
        const hasSudo=f.recommendation.includes('sudo');
        if(!isFlag&&!hasSudo){
          btns+=`<button onclick="fix(this,'${ea(f.recommendation)}')">Применить</button>`;
        }
        h+=`<div class="fi">
          <div class="th">${esc(f.threat)}</div>${lh}
          <div class="fb"><div class="fc" id="${id}">${esc(f.recommendation)}</div>
          <div class="fa">${btns}</div></div></div>`;
      });
      h+='</div></div>';
    });
    r.innerHTML=h;
  }catch(e){b.classList.remove('ld');b.disabled=false;st.textContent='Ошибка';st.style.color='#f55';toast(e.message,0)}
}

function cp(id){navigator.clipboard.writeText(document.getElementById(id).textContent).then(()=>toast('Скопировано',1),()=>toast('Ошибка',0))}

async function fix(btn,cmd){
  if(!confirm('Выполнить?\n'+cmd))return;
  btn.disabled=true;btn.textContent='...';
  try{const d=await(await fetch('/api/fix',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({command:cmd})})).json();
    if(d.ok){btn.textContent='OK';toast('Готово',1)}
    else{btn.textContent='Err';toast(d.stderr||d.error||'Ошибка',0);
      setTimeout(()=>{btn.disabled=false;btn.textContent='Применить'},3000)}
  }catch(e){btn.disabled=false;btn.textContent='Применить';toast('Ошибка',0)}}

async function fixAll(btn,catIdx){
  const cmds=catCmds[catIdx]||[];
  if(!cmds.length){toast('Нет команд',0);return}
  if(!confirm('Применить все исправления ('+cmds.length+') в этой категории?'))return;
  btn.disabled=true;btn.textContent='...';
  try{const d=await(await fetch('/api/fix-all',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({commands:cmds})})).json();
    btn.textContent=d.success+'/'+d.total+' OK';
    toast('Применено: '+d.success+'/'+d.total, d.success===d.total);
  }catch(e){btn.disabled=false;btn.textContent='Ошибка';toast('Ошибка',0)}}

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function ea(s){return s.replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'\\"')}
</script>
</body>
</html>
'''


def open_browser():
    import time; time.sleep(1.2)
    webbrowser.open('http://127.0.0.1:5000')

if __name__ == '__main__':
    root = False
    try: root = os.geteuid() == 0
    except AttributeError: pass
    if not root: print("[!] sudo python3 security_auditor.py")
    print("[*] http://127.0.0.1:5000")
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host='127.0.0.1', port=5000, debug=False)
