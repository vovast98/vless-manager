# -*- coding: utf-8 -*-
import sys
from pathlib import Path
if sys.platform == 'win32' and not getattr(sys, 'frozen', False):
    sys.path.insert(0, str(Path(__file__).parent / ('vendor312' if sys.version_info >= (3, 12) else 'vendor')))

import base64
import copy
import datetime
import json
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import core
import credentials
from transport import SSH, data_dir, resource

APP_VERSION = '1.2.0'
IS_MAC = sys.platform == 'darwin'
UI_FONT = 'Helvetica Neue' if IS_MAC else 'Segoe UI'
TITLE_FONT = 'Helvetica Neue' if IS_MAC else 'Segoe UI Semibold'
MONO_FONT = 'Menlo' if IS_MAC else 'Consolas'
STORAGE_LABEL = 'Связка ключей macOS' if IS_MAC else 'шифрование Windows'
DEFAULTS = {'name': 'Новый сервер', 'host': '', 'port': '22', 'username': 'root', 'keyfile': '', 'config_path': '/usr/local/etc/xray/config.json', 'binary_path': '/usr/local/bin/xray', 'assets_path': '/usr/local/share/xray', 'service': 'xray'}

def public_key(private):
    raw = base64.urlsafe_b64decode(private + '=' * (-len(private) % 4))
    key = X25519PrivateKey.from_private_bytes(raw).public_key()
    return base64.urlsafe_b64encode(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode().rstrip('=')

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('VLESS Manager — управление серверами')
        self.geometry('1320x900'); self.minsize(1100, 740)
        try: self.iconbitmap(str(resource('app.ico')))
        except tk.TclError: pass
        self.configure(bg='#eef2f7')
        self.events = queue.Queue(); self.busy = False; self.ssh = None; self.snapshot = None
        self.profiles = []; self.current_id = None; self.advanced = dict(DEFAULTS)
        self.readonly = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value='Не подключён · изменения заблокированы')
        self.fields = {k: tk.StringVar(value=DEFAULTS[k]) for k in ('name', 'host', 'port', 'username', 'keyfile')}
        self.password = tk.StringVar()
        self.remember_password = tk.BooleanVar(value=True)
        self.check_http = tk.BooleanVar(value=True)
        self.check_urls = tk.StringVar(value='https://www.youtube.com/ https://example.com/')
        self.style_ui(); self.build_ui(); self.load_profiles()
        self.after(70, self.drain); self.protocol('WM_DELETE_WINDOW', self.close_app)

    def style_ui(self):
        s = ttk.Style(self); s.theme_use('clam')
        s.configure('.', font=(UI_FONT, 10), background='#eef2f7', foreground='#17263d')
        s.configure('TFrame', background='#eef2f7')
        s.configure('TLabel', background='#eef2f7')
        s.configure('Title.TLabel', font=(TITLE_FONT, 22), foreground='#10243e')
        s.configure('Sub.TLabel', foreground='#52637b')
        s.configure('TButton', padding=(12, 7), background='#e0e8f2', borderwidth=0)
        s.map('TButton', background=[('active', '#cbdcf0')])
        s.configure('Accent.TButton', background='#245fd6', foreground='white')
        s.map('Accent.TButton', background=[('active', '#1748a9')])
        s.configure('TNotebook', borderwidth=0)
        s.configure('TNotebook.Tab', padding=(12, 9))
        s.map('TNotebook.Tab', background=[('selected', '#ffffff')], foreground=[('selected', '#245fd6')])
        s.configure('Treeview', rowheight=30, background='white', fieldbackground='white', borderwidth=0)
        s.configure('Treeview.Heading', padding=7, font=(TITLE_FONT, 10))
        s.configure('TLabelframe', padding=12)
        s.configure('TEntry', padding=5)

    def button(self, parent, text, command, accent=False):
        return ttk.Button(parent, text=text, command=command, style='Accent.TButton' if accent else 'TButton')

    def build_ui(self):
        head = ttk.Frame(self, padding=(22, 16, 22, 8)); head.pack(fill='x')
        ttk.Label(head, text='VLESS Manager', style='Title.TLabel').pack(side='left')
        ttk.Label(head, text='REALITY + TLS  /  SSH  /  ' + ('macOS' if IS_MAC else 'WINDOWS'), style='Sub.TLabel').pack(side='left', padx=20)
        ttk.Checkbutton(head, text='Только чтение', variable=self.readonly, command=self.mode_changed).pack(side='right')
        ttk.Label(self, textvariable=self.status, style='Sub.TLabel', padding=(24, 0, 20, 9)).pack(fill='x')
        body = ttk.Panedwindow(self, orient='horizontal'); body.pack(fill='both', expand=True, padx=18)
        side = ttk.Frame(body, padding=(0, 8, 12, 0)); body.add(side, weight=0)
        ttk.Label(side, text='МОИ СЕРВЕРЫ', style='Sub.TLabel').pack(anchor='w', pady=(0, 10))
        self.server_list = ttk.Treeview(side, show='tree', selectmode='browse', height=12)
        self.server_list.column('#0', width=205, minwidth=160); self.server_list.pack(fill='both', expand=True)
        self.server_list.bind('<<TreeviewSelect>>', self.select_profile)
        row = ttk.Frame(side); row.pack(fill='x', pady=10)
        self.button(row, '+ Новый', self.new_profile).pack(side='left')
        self.button(row, 'Удалить', self.delete_profile).pack(side='right')
        ttk.Label(side, text='Хранение пароля:\n' + STORAGE_LABEL + '.\nКлюч SSH проверяется\nпри первом подключении.', style='Sub.TLabel').pack(anchor='w', pady=10)
        right = ttk.Frame(body); body.add(right, weight=1)
        conn = ttk.LabelFrame(right, text='Подключение по SSH'); conn.pack(fill='x', pady=(0, 8))
        for col in (1, 3, 5): conn.columnconfigure(col, weight=1)
        for row, items in enumerate([
            [('Название', 'name'), ('Адрес', 'host'), ('SSH-порт', 'port')],
            [('Пользователь', 'username'), ('Пароль / фраза ключа', 'password'), ('SSH-ключ (необязательно)', 'keyfile')],
        ]):
            for n, (label, key) in enumerate(items):
                ttk.Label(conn, text=label).grid(row=row*2, column=n*2, columnspan=2, sticky='w', padx=5, pady=(1, 2))
                variable = self.password if key == 'password' else self.fields[key]
                entry = ttk.Entry(conn, textvariable=variable, show='•' if key == 'password' else '', width=12 if key == 'port' else 22)
                entry.grid(row=row*2+1, column=n*2, columnspan=2, sticky='ew', padx=5, pady=(0, 5))
        controls = ttk.Frame(conn); controls.grid(row=4, column=0, columnspan=6, sticky='ew', pady=(6, 0))
        self.button(controls, 'Подключиться / прочитать', self.connect_server, True).pack(side='left')
        self.button(controls, 'Сохранить профиль', self.save_profile).pack(side='left', padx=7)
        self.button(controls, 'Пути и SSH-ключ', self.connection_options).pack(side='left')
        self.button(controls, 'Проверить задание', self.resume_job).pack(side='right')
        ttk.Checkbutton(conn,text='Сохранять пароль (' + STORAGE_LABEL + ')',variable=self.remember_password).grid(row=5,column=0,columnspan=6,sticky='w',padx=5,pady=(7,0))
        self.tabs = ttk.Notebook(right); self.tabs.pack(fill='both', expand=True)
        names = ['Обзор', 'Установка', 'Перенаправление', 'Исключения', 'Клиенты', 'Конфиг', 'Копии']
        self.pages = {}
        for name in names:
            page = ttk.Frame(self.tabs, padding=14); self.pages[name] = page; self.tabs.add(page, text=name)
        self.build_overview(); self.build_install(); self.build_upstream(); self.build_routes(); self.build_clients(); self.build_config(); self.build_backups()
        footer = ttk.Frame(self, padding=(18, 8, 18, 12)); footer.pack(fill='x')
        row = ttk.Frame(footer); row.pack(fill='x')
        ttk.Label(row, text='ЖУРНАЛ ОПЕРАЦИЙ', style='Sub.TLabel').pack(side='left')
        self.progress = ttk.Progressbar(row, mode='indeterminate', length=180); self.progress.pack(side='right')
        self.log = ScrolledText(footer, height=5, font=(MONO_FONT, 9), bg='#14243c', fg='#d6e5fa', insertbackground='white', relief='flat', wrap='word')
        self.log.pack(fill='x', pady=(5, 0)); self.log.configure(state='disabled')

    def build_overview(self):
        p = self.pages['Обзор']
        ttk.Label(p, text='Состояние сервера', font=(TITLE_FONT, 15)).pack(anchor='w')
        row = ttk.Frame(p); row.pack(fill='x', pady=10)
        buttons=[]
        for n,(label, action) in enumerate([('Обновить', self.connect_server), ('Запустить', lambda:self.service_action('start')), ('Перезапустить', lambda:self.service_action('restart')), ('Остановить', lambda:self.service_action('stop')), ('Проверить HTTPS', self.http_probe), ('Строка подключения', self.overview_uri)]):
            button=self.button(row,label,action,accent=label=='Строка подключения')
            button.grid(row=0,column=n,sticky='w',padx=(0,6),pady=(0,5));buttons.append(button)
        def wrap_toolbar(event):
            x=0;line=0;column=0
            for button in buttons:
                width=button.winfo_reqwidth()+6
                if x and x+width>event.width:line+=1;column=0;x=0
                button.grid_configure(row=line,column=column);x+=width;column+=1
        row.bind('<Configure>',wrap_toolbar)
        self.overview = ScrolledText(p, font=(MONO_FONT, 10), relief='flat', wrap='word', height=10)
        self.overview.pack(fill='both', expand=True)
        checks = ttk.Frame(p); checks.pack(fill='x', pady=(10, 0))
        ttk.Checkbutton(checks, text='HTTPS-проверки после применения (ошибка → откат)', variable=self.check_http).pack(anchor='w')
        ttk.Entry(checks, textvariable=self.check_urls).pack(fill='x', pady=4)
        ttk.Label(checks, text='HTTPS URL через пробел. Проверяются ответы 2xx/3xx через локальный SOCKS. Короткая проверка не гарантирует длительную стабильность.', wraplength=840, style='Sub.TLabel').pack(anchor='w')

    def build_install(self):
        outer = self.pages['Установка']
        canvas=tk.Canvas(outer,bg='#eef2f7',highlightthickness=0)
        scrollbar=ttk.Scrollbar(outer,orient='vertical',command=canvas.yview)
        scrollbar.pack(side='right',fill='y');canvas.pack(side='left',fill='both',expand=True)
        canvas.configure(yscrollcommand=scrollbar.set)
        p=ttk.Frame(canvas);window=canvas.create_window((0,0),window=p,anchor='nw')
        p.bind('<Configure>',lambda e:canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',lambda e:canvas.itemconfigure(window,width=e.width))
        def wheel(event):
            w=event.widget
            while w is not None:
                if w is p or w is canvas:
                    delta = event.delta if IS_MAC else event.delta / 120
                    if delta: canvas.yview_scroll(-(1 if delta > 0 else -1) * max(1, int(abs(delta))), 'units')
                    return
                w=getattr(w,'master',None)
        self.bind('<MouseWheel>',wheel,add=True)
        ttk.Label(p, text='Новый сервер с нуля', font=(TITLE_FONT, 15)).pack(anchor='w')
        ttk.Label(p, text='Debian/Ubuntu · systemd · x86-64 / ARM64. Существующая установка не перезаписывается.', style='Sub.TLabel').pack(anchor='w', pady=(5, 10))
        self.install_fields = {k: tk.StringVar(value=v) for k,v in {'role':'Выходной сервер', 'public_host':'', 'port':'443', 'socks_port':'1080', 'sni':'www.microsoft.com', 'name':'MyVLESS_Reality', 'version':'', 'allow_from':'', 'upstream_vless':'','transport':'tcp','security':'reality','flow':'xtls-rprx-vision','path':'/vless','service_name':'vless','xhttp_mode':'auto','http_host':'','tls_method':'existing','tls_cert_file':'','tls_key_file':'','acme_email':''}.items()}
        form = ttk.Frame(p); form.pack(fill='x'); form.columnconfigure(1, weight=1)
        labels = [('Роль','role'), ('Публичный IP / домен','public_host'), ('Порт VLESS','port'), ('Локальный SOCKS-порт','socks_port'),('Транспорт','transport'),('Защита соединения','security'),('Flow (XTLS Vision)','flow'), ('SNI (Reality: маскировка; TLS: свой домен)','sni'), ('Название подключения','name'), ('Версия Xray (пусто = stable)','version'),('HTTP-путь (XHTTP/WS/HTTPUpgrade)','path'),('gRPC serviceName','service_name'),('Режим клиента XHTTP','xhttp_mode'),('HTTP Host / gRPC authority (необязательно)','http_host'),('TLS: сертификат existing / Let’s Encrypt acme','tls_method'),('TLS: путь к fullchain.pem на сервере','tls_cert_file'),('TLS: путь к privkey.pem на сервере','tls_key_file'),('Let’s Encrypt: email (необязательно)','acme_email'), ('Разрешённые IP/CIDR для выхода','allow_from'), ('VLESS-ссылка выходного сервера','upstream_vless')]
        choices={'role':['Выходной сервер','Входной сервер → выход'],'transport':['tcp','xhttp','grpc','ws','httpupgrade'],'security':['reality','tls'],'flow':['xtls-rprx-vision',''],'xhttp_mode':['auto','packet-up','stream-up','stream-one'],'tls_method':['existing','acme']}
        self.install_controls={}
        for r,(label,key) in enumerate(labels):
            ttk.Label(form,text=label).grid(row=r,column=0,sticky='w',padx=(0,12),pady=3)
            w = ttk.Combobox(form,textvariable=self.install_fields[key],values=choices[key],state='readonly') if key in choices else ttk.Entry(form,textvariable=self.install_fields[key])
            w.grid(row=r,column=1,sticky='ew',pady=3)
            self.install_controls[key]=w
        for key in ('transport','security','tls_method'):self.install_controls[key].bind('<<ComboboxSelected>>',lambda e:self.sync_install_transport())
        self.sync_install_transport()
        self.no_firewall = tk.BooleanVar(value=False)
        ttk.Checkbutton(p,text='Не менять правила UFW/firewalld',variable=self.no_firewall).pack(anchor='w',pady=(8,2))
        self.button(p,'Показать план установки',self.install_server,True).pack(anchor='w',pady=8)
        ttk.Label(p,text='Выходной сервер отправляет принятый трафик в Интернет. Входной сервер пересылает ресурсы из геосписка по указанной ссылке. Ключи, UUID и shortId создаются автоматически.',style='Sub.TLabel',wraplength=820).pack(anchor='w')
        ttk.Label(p,text='Reality: TCP/RAW, XHTTP, gRPC. TLS: все пять транспортов, нужен сертификат для своего домена. Vision доступен только для TCP/RAW. Для acme домен должен указывать на сервер и TCP 80 должен быть доступен извне.',style='Sub.TLabel',wraplength=820).pack(anchor='w',pady=8)

    def sync_install_transport(self):
        fields=self.install_fields;network=fields['transport'].get();security=fields['security'].get()
        if network in ('ws','httpupgrade'):fields['security'].set('tls');security='tls'
        if security=='tls'and fields['sni'].get()=='www.microsoft.com':
            domain=fields['public_host'].get().strip()or self.fields['host'].get().strip()
            try:__import__('ipaddress').ip_address(domain);domain=''
            except ValueError:pass
            fields['sni'].set(domain)
        elif security=='reality'and not fields['sni'].get():fields['sni'].set('www.microsoft.com')
        self.install_controls['security'].configure(values=['tls']if network in ('ws','httpupgrade')else['reality','tls'])
        self.install_controls['flow'].configure(values=['xtls-rprx-vision','']if network=='tcp'else[''])
        if network!='tcp':fields['flow'].set('')
        active={'path':network in ('xhttp','ws','httpupgrade'),'service_name':network=='grpc','xhttp_mode':network=='xhttp','http_host':network!='tcp','tls_method':security=='tls','tls_cert_file':security=='tls'and fields['tls_method'].get()=='existing','tls_key_file':security=='tls'and fields['tls_method'].get()=='existing','acme_email':security=='tls'and fields['tls_method'].get()=='acme'}
        for name,enabled in active.items():
            widget=self.install_controls[name];widget.configure(state=('readonly'if isinstance(widget,ttk.Combobox)else'normal')if enabled else'disabled')

    def build_upstream(self):
        p=self.pages['Перенаправление']
        ttk.Label(p,text='Куда отправлять трафик',font=(TITLE_FONT,15)).pack(anchor='w')
        ttk.Label(p,text='VLESS-ссылка выхода: TCP/RAW, XHTTP, gRPC, WebSocket или HTTPUpgrade; Reality/TLS.',style='Sub.TLabel').pack(anchor='w',pady=8)
        self.upstream_link=ScrolledText(p,height=4,font=(MONO_FONT,10),wrap='word');self.upstream_link.pack(fill='x')
        self.upstream_tag=tk.StringVar(value='upstream');self.routing_mode=tk.StringVar(value='Сохранить текущие правила')
        row=ttk.Frame(p);row.pack(fill='x',pady=12)
        ttk.Label(row,text='Выход:').pack(side='left',padx=(0,8))
        self.tag_combo=ttk.Combobox(row,textvariable=self.upstream_tag,width=25);self.tag_combo.pack(side='left')
        ttk.Combobox(row,textvariable=self.routing_mode,state='readonly',values=['Сохранить текущие правила','Добавить геосписок заблокированных','Остальной трафик через выход'],width=39).pack(side='left',padx=12)
        self.button(p,'Сравнить и применить перенаправление',self.plan_upstream,True).pack(anchor='w')
        self.button(p,'Обновить геобазу с проверкой SHA256',self.update_geo).pack(anchor='w',pady=12)
        ttk.Label(p,text='Существующие правила сохраняются. Режим «Остальной трафик» добавляет правило в конец: более ранние исключения имеют приоритет. Геосписок скачивается при необходимости.',style='Sub.TLabel',wraplength=830).pack(anchor='w')

    def build_routes(self):
        p=self.pages['Исключения']
        ttk.Label(p,text='Ручные маршруты',font=(TITLE_FONT,15)).pack(anchor='w')
        self.routes=ttk.Treeview(p,columns=('route','target'),show='headings',selectmode='browse',height=7)
        self.routes.heading('route',text='Маршрут');self.routes.heading('target',text='Домен / IP / CIDR');self.routes.column('route',width=150,stretch=False)
        self.routes.pack(fill='both',expand=True,pady=10)
        self.route_target=tk.StringVar();self.route_kind=tk.StringVar(value='Через выход')
        row=ttk.Frame(p);row.pack(fill='x')
        ttk.Entry(row,textvariable=self.route_target).pack(side='left',fill='x',expand=True)
        ttk.Combobox(row,textvariable=self.route_kind,values=['Через выход','Напрямую','Блокировать'],state='readonly',width=18).pack(side='left',padx=8)
        self.button(row,'Добавить / заменить',self.add_route).pack(side='left')
        self.button(p,'Удалить выбранное исключение',self.remove_route).pack(anchor='w',pady=10)
        ttk.Label(p,text='Например: hermes-assets.nousresearch.com, full:host.example.com, 203.0.113.0/24. Обычный домен включает поддомены. Изменения требуют перезапуска и разрывают текущие соединения.',wraplength=830,style='Sub.TLabel').pack(anchor='w')

    def build_clients(self):
        p=self.pages['Клиенты']
        ttk.Label(p,text='Клиенты и вход VLESS',font=(TITLE_FONT,15)).pack(anchor='w')
        self.clients=ttk.Treeview(p,columns=('input','name','uuid'),show='headings',height=7,selectmode='browse')
        for k,title in [('input','Вход'),('name','Клиент'),('uuid','UUID')]:self.clients.heading(k,text=title)
        self.clients.column('input',width=85,stretch=False);self.clients.column('name',width=150,stretch=False)
        self.clients.pack(fill='both',expand=True,pady=10)
        row=ttk.Frame(p);row.pack(fill='x')
        for label,action in [('Новый клиент',self.add_client),('Удалить клиента',self.remove_client),('Строка подключения',self.show_uri),('Параметры входа',self.inbound_options)]:self.button(row,label,action).pack(side='left',padx=(0,7))
        ttk.Label(p,text='Ссылка формируется из текущих настроек входа. Удаление клиента и изменение входа применяются только после просмотра различий.',style='Sub.TLabel',wraplength=830).pack(anchor='w',pady=12)

    def build_config(self):
        p=self.pages['Конфиг']
        row=ttk.Frame(p);row.pack(fill='x',pady=(0,8))
        self.button(row,'Заново прочитать',self.connect_server).pack(side='left')
        self.button(row,'Открыть JSON с диска',self.import_json).pack(side='left',padx=6)
        self.button(row,'Экспортировать JSON',self.export_json).pack(side='left')
        self.button(row,'Показать изменения',self.plan_json,True).pack(side='right')
        self.config_editor=ScrolledText(p,font=(MONO_FONT,10),wrap='none',undo=True);self.config_editor.pack(fill='both',expand=True)
        ttk.Label(p,text='JSON содержит приватные ключи. Экспорт сохраняет их в выбранный вами файл.',style='Sub.TLabel').pack(anchor='w',pady=(7,0))

    def build_backups(self):
        p=self.pages['Копии']
        ttk.Label(p,text='Резервные копии программы',font=(TITLE_FONT,15)).pack(anchor='w')
        self.backups=ttk.Treeview(p,columns=('time','reason'),show='headings',height=8,selectmode='browse')
        self.backups.heading('time',text='Время UTC');self.backups.heading('reason',text='Перед какой операцией');self.backups.column('time',width=225,stretch=False)
        self.backups.pack(fill='both',expand=True,pady=12)
        self.button(p,'Сравнить и восстановить выбранную копию',self.restore_backup,True).pack(anchor='w')
        ttk.Label(p,text='Перед каждым применением сохраняются конфиг и состояние исключений; при обновлении списка — также геобаза. Восстановление тоже создаёт новую резервную копию.',wraplength=830,style='Sub.TLabel').pack(anchor='w',pady=12)

    def emit(self,message):
        self.events.put(('log',str(message)))

    def drain(self):
        try:
            while True:
                item=self.events.get_nowait()
                if item[0]=='call': item[1]()
                elif item[0]=='log':
                    self.log.configure(state='normal');self.log.insert('end',item[1]+'\n')
                    if int(self.log.index('end-1c').split('.')[0])>900:self.log.delete('1.0','300.0')
                    self.log.see('end');self.log.configure(state='disabled')
                elif item[0]=='ask':
                    _,title,text,event,result=item
                    result['yes']=messagebox.askyesno(title,text,parent=self);event.set()
        except queue.Empty:pass
        self.after(70,self.drain)

    def thread_confirm(self,title,text):
        event=threading.Event();result={};self.events.put(('ask',title,text,event,result));event.wait()
        return result.get('yes',False)

    def task(self,title,fn,done=None):
        if self.busy:messagebox.showinfo('Операция выполняется','Дождитесь завершения текущей операции.',parent=self);return
        self.busy=True;self.freeze_controls();self.progress.start(12);self.status.set(title)
        def worker():
            try:
                value=fn()
                self.events.put(('call',lambda:self.finish_task(value,done)))
            except Exception as exc:
                msg=str(exc)
                self.events.put(('call',lambda:self.fail_task(msg)))
        threading.Thread(target=worker,daemon=True).start()

    def finish_task(self,value,done):
        self.busy=False;self.unfreeze_controls();self.progress.stop();self.mode_changed()
        if done:done(value)

    def fail_task(self,msg):
        self.busy=False;self.unfreeze_controls();self.progress.stop();self.status.set('Операция не завершена')
        self.emit('Ошибка: '+msg);messagebox.showerror('VLESS Manager',msg,parent=self)

    def freeze_controls(self):
        self.frozen_controls=[]
        def visit(parent):
            for w in parent.winfo_children():
                if isinstance(w,(ttk.Button,ttk.Entry,ttk.Combobox,ttk.Checkbutton)):
                    self.frozen_controls.append((w,w.state()));w.state(['disabled'])
                visit(w)
        visit(self)

    def unfreeze_controls(self):
        for w,state in getattr(self,'frozen_controls',[]):
            try:
                w.state(['!disabled','!readonly']);w.state(state)
            except tk.TclError:pass
        self.frozen_controls=[]

    def mode_changed(self):
        if self.busy:return
        prefix='Только чтение' if self.readonly.get() else 'Изменения разрешены после подтверждения'
        self.status.set(prefix+(' · '+self.fields['host'].get() if self.snapshot else ' · не подключён'))

    def write_allowed(self):
        if self.busy:raise ValueError('Дождитесь текущей операции')
        if self.readonly.get():
            messagebox.showinfo('Только чтение','Для применения снимите флажок «Только чтение». Подключение и просмотр доступны без изменений.',parent=self);return False
        return True

    def need_config(self):
        if not self.snapshot or not self.snapshot.get('installed'):raise ValueError('Сначала подключитесь к существующему серверу')
        self.require_same_connection()
        return self.snapshot['config']

    def require_same_connection(self):
        if not self.ssh or any(self.profile()[k]!=self.ssh.profile.get(k) for k in ('host','port','username','keyfile','config_path','binary_path','assets_path','service')):
            raise ValueError('Параметры подключения изменились. Нажмите «Подключиться / прочитать».')

    def profile(self):
        p=self.advanced.copy();p.update({k:v.get().strip() for k,v in self.fields.items()})
        # Local credential metadata must not be sent to remote jobs or SSH probes.
        for key in ('password_protected','save_password','password','passphrase'):p.pop(key,None)
        if p['host']:p['host']=core.host(p['host'])
        try:port=int(p['port'])
        except ValueError:raise ValueError('SSH-порт должен быть числом')
        if not 1<=port<=65535:raise ValueError('Некорректный SSH-порт')
        p['port']=str(port);p['id']=self.current_id or uuid.uuid4().hex
        return p

    def load_profiles(self):
        try:self.profiles=json.loads((data_dir()/'profiles.json').read_text(encoding='utf-8'))
        except (OSError,ValueError):self.profiles=[]
        self.refresh_profiles()
        if self.profiles:self.load_profile(self.profiles[0])

    def persist_profiles(self):
        p=data_dir()/'profiles.json';tmp=p.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.profiles,ensure_ascii=False,indent=2),encoding='utf-8')
        if IS_MAC: tmp.chmod(0o600)
        os.replace(tmp,p)
        for profile in self.profiles:
            if not profile.get('password_protected'):
                self.forget_password(profile['id'])

    def forget_password(self, profile_id):
        try: credentials.forget(profile_id)
        except RuntimeError as exc: self.emit(str(exc))

    def refresh_profiles(self):
        self.server_list.delete(*self.server_list.get_children())
        for p in self.profiles:self.server_list.insert('', 'end',iid=p['id'],text=p.get('name') or p['host'])

    def load_profile(self,p):
        if self.ssh:self.ssh.close()
        self.ssh=None;self.snapshot=None;self.current_id=p['id'];self.advanced={**DEFAULTS,**p}
        for k,v in self.fields.items():v.set(p.get(k,DEFAULTS[k]))
        self.password.set('');self.remember_password.set(p.get('save_password',True))
        if p.get('password_protected') and self.remember_password.get():
            try:self.password.set(credentials.unprotect(p['password_protected'],p['id']))
            except (ValueError,RuntimeError,UnicodeError):
                self.emit('Не удалось расшифровать пароль профиля. Введите его заново и сохраните профиль в текущей учётной записи компьютера.')
        self.clear_snapshot();self.mode_changed()

    def profile_with_password(self,p):
        p=p.copy()
        for key in ('password','passphrase','password_protected'):p.pop(key,None)
        p['save_password']=self.remember_password.get()
        if p['save_password'] and self.password.get():
            p['password_protected']=credentials.protect(self.password.get(),p['id'])
        return p

    def select_profile(self,event=None):
        selected=self.server_list.selection()
        if not selected or selected[0]==self.current_id:return
        if self.busy:return
        self.load_profile(next(p for p in self.profiles if p['id']==selected[0]))

    def new_profile(self):
        if self.busy:return
        self.load_profile({**DEFAULTS,'id':uuid.uuid4().hex})

    def save_profile(self):
        if self.busy:return
        try:
            p=self.profile()
            if not p['host']:raise ValueError('Укажите адрес сервера')
            self.current_id=p['id']
            old=next((x for x in self.profiles if x['id']==p['id']),None)
            p=self.profile_with_password({**old,**p}if old else p)
            if old:self.profiles[self.profiles.index(old)]=p
            else:self.profiles.append(p)
            self.persist_profiles();self.refresh_profiles();self.emit('Профиль сохранён'+(' с зашифрованным паролем.'if p.get('password_protected')else' без пароля.'))
        except Exception as e:messagebox.showerror('Профиль',str(e),parent=self)

    def delete_profile(self):
        if self.busy:return
        if messagebox.askyesno('Удалить профиль','Удалить только локальный профиль? Сервер останется без изменений.',parent=self):
            removed_id=self.current_id
            self.profiles=[p for p in self.profiles if p['id']!=removed_id];self.persist_profiles()
            self.forget_password(removed_id);self.refresh_profiles();self.new_profile()

    def clear_snapshot(self):
        for tree in (self.routes,self.clients,self.backups):tree.delete(*tree.get_children())
        for text in (self.overview,self.config_editor):text.delete('1.0','end')

    def connection_options(self):
        if self.busy:return
        dialog=tk.Toplevel(self);dialog.title('Пути и ключ SSH');dialog.transient(self);dialog.grab_set();dialog.geometry('720x390')
        values={k:tk.StringVar(value=self.advanced.get(k,DEFAULTS[k])) for k in ('config_path','binary_path','assets_path','service')}
        for r,(k,label) in enumerate([('config_path','Конфиг Xray'),('binary_path','Бинарник Xray'),('assets_path','Каталог геобаз'),('service','Служба systemd')]):
            ttk.Label(dialog,text=label).grid(row=r,column=0,padx=15,pady=8,sticky='w');ttk.Entry(dialog,textvariable=values[k],width=60).grid(row=r,column=1,padx=10,pady=8,sticky='ew')
        ttk.Label(dialog,text='SSH-ключ').grid(row=4,column=0,padx=15,sticky='w');ttk.Entry(dialog,textvariable=self.fields['keyfile']).grid(row=4,column=1,padx=10,sticky='ew')
        self.button(dialog,'Выбрать файл',lambda:self.fields['keyfile'].set(filedialog.askopenfilename(parent=dialog) or self.fields['keyfile'].get())).grid(row=5,column=1,sticky='w',padx=10,pady=8)
        ttk.Label(dialog,text='Для изменений нужен root. Поддерживается единый JSON-конфиг; confdir автоматически не изменяется.',wraplength=650).grid(row=6,column=0,columnspan=2,padx=15,pady=10)
        def save():self.advanced.update({k:v.get().strip() for k,v in values.items()});dialog.destroy()
        self.button(dialog,'Готово',save,True).grid(row=7,column=1,sticky='e',padx=12,pady=10);dialog.columnconfigure(1,weight=1)

    def connect_server(self):
        try:
            p=self.profile()
            if not p['host']:raise ValueError('Укажите адрес сервера')
            if self.busy:return
            if self.ssh:self.ssh.close()
            self.snapshot=None;self.clear_snapshot()
            self.ssh=SSH(p,self.password.get(),self.thread_confirm)
            ssh=self.ssh
            self.task('Чтение сервера…',lambda:ssh.inspect(p),self.fill_snapshot)
        except Exception as e:messagebox.showerror('Подключение',str(e),parent=self)

    def fill_snapshot(self,snapshot):
        self.snapshot=snapshot;self.clear_snapshot()
        c=snapshot.get('config')
        text='СЕРВЕР: '+snapshot['hostname']+'\n\n'+snapshot.get('version','')+'\n\n'+snapshot.get('service','')+'\n\n'+snapshot.get('network','')+'\n\n'+snapshot.get('sockets','')+'\n\nПОСЛЕДНИЕ СОБЫТИЯ\n'+snapshot.get('logs','')
        self.overview.insert('1.0',text)
        if c:
            self.config_editor.insert('1.0',core.encode(c).decode())
            labels={'proxy':'Через выход','direct':'Напрямую','block':'Блокировать'}
            for n,e in enumerate(core.route_state(c)['entries']):self.routes.insert('','end',iid=str(n),values=(labels[e['route']],e['value']))
            for n,i in enumerate(c['inbounds']):
                if i.get('protocol')=='vless':
                    for m,u in enumerate(i.get('settings',{}).get('clients',[])):
                        self.clients.insert('','end',iid='%d:%d'%(n,m),values=(i.get('port'),u.get('email','Клиент '+str(m+1)),u.get('id','')))
            tags=[o['tag']for o in c.get('outbounds',[])if o.get('protocol')=='vless' and o.get('tag')]
            self.tag_combo.configure(values=tags);self.upstream_tag.set(core.proxy_tag(c))
        for b in snapshot.get('backups',[]):self.backups.insert('','end',iid=b['id'],values=(b['time'],b['reason']))
        self.install_fields['public_host'].set(self.fields['host'].get())
        self.emit('Сведения прочитаны. '+('Xray найден.' if c else 'Конфиг не найден; доступна чистая установка.'))
        self.mode_changed()

    def guarded(self,fn):
        try:return fn()
        except Exception as e:messagebox.showerror('Проверка',str(e),parent=self)

    def review(self,candidate,reason,update_geo=False,restore_id=None):
        original=self.need_config();core.encode(candidate)
        request={**self.profile(),'action':'restore' if restore_id else 'apply','expected_sha':self.snapshot['config_sha'],'state_sha':self.snapshot['state_sha'],'config':candidate,'reason':reason,'update_geo':update_geo,'check_urls':self.check_urls.get().split() if self.check_http.get() else []}
        if restore_id:request['backup_id']=restore_id
        dialog=tk.Toplevel(self);dialog.title('Просмотр изменений');dialog.geometry('1020x740');dialog.transient(self);dialog.grab_set()
        ttk.Label(dialog,text=reason,font=(TITLE_FONT,15),padding=12).pack(anchor='w')
        ttk.Label(dialog,text='Применение перезапустит Xray и разорвёт текущие соединения. Перед записью — резервная копия, при ошибке проверки — откат.',wraplength=950,padding=(12,0,12,10)).pack(anchor='w')
        if update_geo:ttk.Label(dialog,text='Будет загружена геобаза с проверкой SHA256. В копию войдёт прежняя база.',padding=12).pack(anchor='w')
        text=ScrolledText(dialog,font=(MONO_FONT,10),wrap='none');text.pack(fill='both',expand=True,padx=12);text.insert('1.0',core.config_diff(original,candidate));text.configure(state='disabled')
        ttk.Label(dialog,text='Проверки: '+(', '.join(request['check_urls']) if request['check_urls'] else 'только запуск службы и TCP-порты; HTTPS не проверяется'),wraplength=950,padding=12).pack(anchor='w')
        row=ttk.Frame(dialog,padding=12);row.pack(fill='x')
        self.button(row,'Закрыть без изменений',dialog.destroy).pack(side='left')
        def apply():
            if self.write_allowed():dialog.destroy();self.run_job(request)
        self.button(row,'Применить с резервной копией',apply,True).pack(side='right')

    def plan_upstream(self):
        def action():
            c=self.need_config();tag=self.upstream_tag.get().strip()
            if not tag or any(ch.isspace() for ch in tag):raise ValueError('Укажите тег выхода без пробелов')
            new=core.replace_upstream(c,self.upstream_link.get('1.0','end'),tag)
            modes={'Сохранить текущие правила':'keep','Добавить геосписок заблокированных':'blocked','Остальной трафик через выход':'all'}
            mode=modes[self.routing_mode.get()];new=core.geo_route(new,tag,mode)
            endpoint=new['outbounds'][next(i for i,o in enumerate(new['outbounds'])if o.get('tag')==tag)]['settings']['vnext'][0]
            if endpoint['address']==self.fields['host'].get() and any(i.get('port')==endpoint['port']for i in c['inbounds']):raise ValueError('Получится перенаправление на свой вход')
            self.review(new,'Изменение перенаправления → '+core.outbound_summary(new['outbounds'][next(i for i,o in enumerate(new['outbounds'])if o.get('tag')==tag)]),update_geo=mode=='blocked' and not self.snapshot.get('geo_present'))
        self.guarded(action)

    def update_geo(self):
        self.guarded(lambda:self.review(copy.deepcopy(self.need_config()),'Обновление геобазы',update_geo=True))

    def add_route(self):
        self.guarded(lambda:self.review(core.change_route(self.need_config(),{'Через выход':'proxy','Напрямую':'direct','Блокировать':'block'}[self.route_kind.get()],self.route_target.get()),'Добавление / изменение исключения'))

    def remove_route(self):
        def action():
            sel=self.routes.selection()
            if not sel:raise ValueError('Выберите исключение')
            target=self.routes.item(sel[0],'values')[1]
            self.review(core.change_route(self.need_config(),'proxy',target,remove=True),'Удаление исключения '+target)
        self.guarded(action)

    def selected_client(self):
        self.need_config();sel=self.clients.selection()
        if not sel:raise ValueError('Выберите клиента')
        return tuple(int(x)for x in sel[0].split(':'))

    def add_client(self):
        def action():
            c=copy.deepcopy(self.need_config());sel=self.clients.selection()
            indices=[n for n,i in enumerate(c['inbounds'])if i.get('protocol')=='vless' and i.get('streamSettings',{}).get('security')in ('reality','tls')]
            if not indices:raise ValueError('Нет входа VLESS Reality/TLS')
            n=int(sel[0].split(':')[0]) if sel else indices[0]
            name=simpledialog.askstring('Новый клиент','Имя клиента (email-метка):',parent=self)
            if not name:return
            clients=c['inbounds'][n]['settings']['clients']
            if any(u.get('email')==name for u in clients):raise ValueError('Такая метка уже существует')
            stream=c['inbounds'][n].get('streamSettings',{})
            flow=clients[0].get('flow','')if clients else('xtls-rprx-vision'if stream.get('network',stream.get('method','tcp'))in ('raw','tcp')else'')
            clients.append({'id':str(uuid.uuid4()),'email':name,'flow':flow})
            self.review(c,'Добавление нового клиента')
        self.guarded(action)

    def remove_client(self):
        def action():
            n,m=self.selected_client();c=copy.deepcopy(self.need_config())
            if len(c['inbounds'][n]['settings']['clients'])==1:raise ValueError('Последнего клиента удалить нельзя; остановите службу при необходимости')
            del c['inbounds'][n]['settings']['clients'][m];self.review(c,'Удаление клиента')
        self.guarded(action)

    def show_text(self,title,content):
        d=tk.Toplevel(self);d.title(title);d.geometry('900x340');d.transient(self)
        text=ScrolledText(d,font=(MONO_FONT,11),wrap='word');text.pack(fill='both',expand=True,padx=14,pady=14);text.insert('1.0',content)
        def copy_text():self.clipboard_clear();self.clipboard_append(content)
        self.button(d,'Скопировать',copy_text,True).pack(pady=(0,14))

    def show_uri(self):
        def action():
            n,m=self.selected_client();self.show_client_uri(n,m)
        self.guarded(action)

    def show_client_uri(self,n,m):
        c=self.need_config();i=c['inbounds'][n];stream=i.get('streamSettings',{})
        if i.get('protocol')!='vless' or stream.get('security')not in ('reality','tls'):raise ValueError('Выбран вход без VLESS Reality/TLS')
        key=public_key(stream['realitySettings']['privateKey'])if stream['security']=='reality'else''
        if stream['security']=='tls'and not stream.get('tlsSettings',{}).get('serverName'):
            sni=simpledialog.askstring('TLS-ссылка','Укажите домен сертификата (SNI):',initialvalue=self.fields['host'].get(),parent=self)
            if not sni:return
            c=copy.deepcopy(c);c['inbounds'][n]['streamSettings']['tlsSettings']['serverName']=core.host(sni)
        name=i['settings']['clients'][m].get('email')or self.fields['name'].get()
        self.show_text('Готовая строка подключения',core.client_uri(c,self.fields['host'].get(),key,n,m,name))

    def overview_uri(self):
        def action():
            c=self.need_config();choices=[]
            for n,i in enumerate(c.get('inbounds',[])):
                stream=i.get('streamSettings',{})
                if i.get('protocol')!='vless' or stream.get('security')not in ('reality','tls') or stream.get('network',stream.get('method','tcp'))not in ('tcp','raw','xhttp','splithttp','grpc','ws','websocket','httpupgrade'):continue
                for m,user in enumerate(i.get('settings',{}).get('clients',[])):
                    choices.append((n,m,i,user))
            if not choices:raise ValueError('На сервере нет клиентов поддерживаемого VLESS Reality/TLS для создания ссылки')
            if len(choices)==1:
                n,m,_,_=choices[0];self.show_client_uri(n,m);return
            dialog=tk.Toplevel(self);dialog.title('Выберите подключение');dialog.geometry('820x370');dialog.transient(self);dialog.grab_set()
            ttk.Label(dialog,text='Для какого клиента создать VLESS-ссылку?',font=(TITLE_FONT,13),padding=12).pack(anchor='w')
            table=ttk.Treeview(dialog,columns=('port','name','uuid'),show='headings',selectmode='browse',height=6)
            for key,title in [('port','Порт входа'),('name','Клиент'),('uuid','UUID')]:table.heading(key,text=title)
            table.column('port',width=90,stretch=False);table.column('name',width=180,stretch=False)
            table.pack(fill='both',expand=True,padx=12,pady=(0,10))
            for n,m,i,user in choices:table.insert('','end',iid='%d:%d'%(n,m),values=(i.get('port'),user.get('email')or'Клиент '+str(m+1),user.get('id','')))
            table.selection_set(table.get_children()[0])
            def generate(event=None):
                selection=table.selection()
                if not selection:return
                n,m=(int(x)for x in selection[0].split(':'));dialog.destroy();self.guarded(lambda:self.show_client_uri(n,m))
            table.bind('<Double-1>',generate)
            controls=ttk.Frame(dialog,padding=12);controls.pack(fill='x')
            self.button(controls,'Отмена',dialog.destroy).pack(side='left')
            self.button(controls,'Создать ссылку',generate,True).pack(side='right')
        self.guarded(action)

    def inbound_options(self):
        def action():
            n,_=self.selected_client();c=self.need_config();i=c['inbounds'][n]
            if i.get('streamSettings',{}).get('security')!='reality':
                self.tabs.select(self.pages['Конфиг']);messagebox.showinfo('Настройка TLS','Параметры TLS и путей сертификатов доступны в JSON-конфиге. Перед применением будет показана разница.',parent=self);return
            r=i['streamSettings']['realitySettings']
            d=tk.Toplevel(self);d.title('Параметры входа Reality');d.geometry('740x350');d.transient(self);d.grab_set()
            variables={k:tk.StringVar(value=str(v))for k,v in {'port':i['port'],'sni':r['serverNames'][0],'target':r.get('target',r.get('dest',''))}.items()}
            for row,(k,label)in enumerate([('port','Порт VLESS'),('sni','SNI'),('target','Домен маскировки:порт')]):
                ttk.Label(d,text=label).grid(row=row,column=0,padx=15,pady=12,sticky='w');ttk.Entry(d,textvariable=variables[k],width=55).grid(row=row,column=1,padx=10,pady=12)
            rotate=tk.BooleanVar(value=False)
            ttk.Checkbutton(d,text='Создать новые ключи Reality и shortId (все старые ссылки перестанут работать)',variable=rotate).grid(row=3,column=0,columnspan=2,padx=15,pady=12,sticky='w')
            ttk.Label(d,text='При смене порта правила внешнего firewall нужно проверить отдельно.',wraplength=650).grid(row=4,column=0,columnspan=2,padx=15,pady=8)
            def plan():
                def change():
                    candidate=copy.deepcopy(c);inp=candidate['inbounds'][n];rr=inp['streamSettings']['realitySettings']
                    port=int(variables['port'].get())
                    if not 1<=port<=65535:raise ValueError('Некорректный порт')
                    inp['port']=port;rr['serverNames']=[core.host(variables['sni'].get())];rr['target' if 'target'in rr else 'dest']=variables['target'].get().strip()
                    if rotate.get():
                        key=X25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
                        rr['privateKey']=base64.urlsafe_b64encode(key).decode().rstrip('=');rr['shortIds']=[os.urandom(8).hex()]
                    d.destroy();self.review(candidate,'Изменение параметров входа Reality')
                self.guarded(change)
            self.button(d,'Показать изменения',plan,True).grid(row=5,column=1,sticky='e',padx=12,pady=12)
        self.guarded(action)

    def plan_json(self):self.guarded(lambda:self.review(json.loads(self.config_editor.get('1.0','end')),'Изменение JSON-конфига'))

    def import_json(self):
        path=filedialog.askopenfilename(filetypes=[('JSON','*.json'),('Все файлы','*.*')],parent=self)
        if path:
            def action():
                text=core.encode(json.loads(Path(path).read_text(encoding='utf-8-sig'))).decode();self.config_editor.delete('1.0','end');self.config_editor.insert('1.0',text)
            self.guarded(action)

    def export_json(self):
        path=filedialog.asksaveasfilename(defaultextension='.json',filetypes=[('JSON','*.json')],parent=self)
        if path:self.guarded(lambda:Path(path).write_bytes(core.encode(json.loads(self.config_editor.get('1.0','end')))))

    def install_server(self):
        def action():
            p=self.profile()
            if not p['host']:raise ValueError('Укажите SSH-адрес сервера')
            v={k:x.get().strip()for k,x in self.install_fields.items()}
            role='entry' if v.pop('role')=='Входной сервер → выход'else'exit'
            v['public_host']=core.host(v['public_host'] or p['host'])
            for field in ('port','socks_port'):
                v[field]=int(v[field])
                if not 1<=v[field]<=65535:raise ValueError('Некорректный порт')
            if v['port']==v['socks_port']:raise ValueError('Порты VLESS и SOCKS должны различаться')
            v['sni']=core.host(v['sni']);v['version']=v['version']or None
            core.vless_profile.profile(v)
            if v['security']=='tls':
                try:__import__('ipaddress').ip_address(v['sni'])
                except ValueError:pass
                else:raise ValueError('Для TLS укажите свой домен сертификата в SNI')
                if v['tls_method']=='existing'and(not v['tls_cert_file'].startswith('/')or not v['tls_key_file'].startswith('/')):raise ValueError('Для TLS укажите пути сертификата и ключа на сервере либо выберите acme')
                if v['tls_method']=='acme'and v['acme_email']and not __import__('re').fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',v['acme_email']):raise ValueError('Некорректный email Let’s Encrypt')
                if v['tls_method']=='acme'and v['port']==80:raise ValueError('TCP 80 нужен для продления сертификата. Выберите другой порт VLESS.')
            if role=='entry':core.parse_vless(v['upstream_vless'])
            v['no_firewall']=self.no_firewall.get();v['only_blocked']=False
            if not self.write_allowed():return
            plan='Сервер: %s\nРоль: %s\nVLESS: %s:%s\nSNI: %s\nXray: %s\n\nБудут установлены системные зависимости и Xray, созданы ключи и служба. Для входного сервера — геобаза и таймер обновления.\n\nСуществующая установка не перезаписывается. Открытие порта в панели хостинга выполняется отдельно.\n\nНачать установку?'%(p['host'],'входной → выход'if role=='entry'else'выходной',v['public_host'],v['port'],v['sni'],v['version']or'последний стабильный релиз')
            details='Транспорт: '+v['transport']+' / '+v['security']+'\nFlow: '+(v['flow']or'без Vision')+'\n'
            if v['security']=='tls':
                if v['tls_method']=='acme':details+='Сертификат: Let’s Encrypt HTTP-01. Подтверждение означает согласие с условиями сервиса (https://letsencrypt.org/repository/). Будут установлены Certbot, таймер продления и deploy-hook; при разрешённой настройке firewall откроется TCP 80 для проверки и продления.\n'
                else:details+='TLS-сертификат будет скопирован из указанных файлов. Его продление и обновление копии нужно настроить отдельно.\n'
            plan=details+'\n'+plan
            if not messagebox.askyesno('План чистой установки',plan,parent=self):return
            v['acme_agree']=v['security']=='tls'and v['tls_method']=='acme'
            if self.ssh:self.ssh.close()
            self.ssh=SSH(p,self.password.get(),self.thread_confirm)
            self.run_job({**p,'action':'install','role':role,'options':v})
        self.guarded(action)

    def save_pending(self,ident):
        p=self.profile();self.current_id=p['id'];p['pending_job']=ident
        old=next((x for x in self.profiles if x['id']==p['id']),None)
        p=self.profile_with_password({**old,**p}if old else p)
        if old:self.profiles[self.profiles.index(old)]=p
        else:self.profiles.append(p)
        self.persist_profiles();self.refresh_profiles()

    def run_job(self,request):
        if not self.ssh:raise ValueError('Сначала подключитесь к серверу')
        ssh=self.ssh
        def worker():
            ident=ssh.submit(request);self.events.put(('call',lambda:self.save_pending(ident)));self.emit('Задание на сервере: '+ident)
            return self.wait_job(ssh,ident)
        self.task('Применение на сервере…',worker,self.job_complete)

    def wait_job(self,ssh,ident):
        previous='';deadline=time.monotonic()+1500;errors=0
        while time.monotonic()<deadline:
            try:
                report=ssh.job(ident);errors=0
                text=report['log']
                if text!=previous:
                    self.emit(text[len(previous):]if text.startswith(previous)else text);previous=text
                if report['result'] is not None:return report['result']
            except (OSError,EOFError,RuntimeError)as e:
                errors+=1
                if errors>=4:raise RuntimeError('Связь прервана. Задание '+ident+' могло продолжиться на сервере. Подключитесь заново и нажмите «Проверить задание».')from e
                ssh.close();self.emit('Восстановление SSH-соединения…')
            time.sleep(2)
        raise RuntimeError('Истекло время ожидания. Проверьте задание '+ident+' кнопкой «Проверить задание».')

    def job_complete(self,result):
        self.advanced.pop('pending_job',None)
        for p in self.profiles:
            if p['id']==self.current_id:p.pop('pending_job',None)
        self.persist_profiles();self.emit(result.get('message',''))
        if result.get('client_uri'):self.show_text('Сервер установлен — готовая VLESS-ссылка',result['client_uri'])
        if result.get('ok'):messagebox.showinfo('Завершено',result.get('message','Готово'),parent=self)
        else:messagebox.showerror('Задание завершилось ошибкой',result.get('message','См. журнал'),parent=self)
        self.connect_server()

    def resume_job(self):
        def action():
            p=next((p for p in self.profiles if p['id']==self.current_id),None)
            ident=p.get('pending_job')if p else None
            if not ident:raise ValueError('В профиле нет незавершённого задания')
            if not self.ssh:self.ssh=SSH(self.profile(),self.password.get(),self.thread_confirm)
            self.task('Чтение состояния задания…',lambda:self.wait_job(self.ssh,ident),self.job_complete)
        self.guarded(action)

    def service_action(self,action):
        def operation():
            self.need_config()
            if not self.write_allowed():return
            labels={'start':'Запустить','stop':'Остановить','restart':'Перезапустить'}
            if messagebox.askyesno('Управление службой',labels[action]+' Xray на '+self.fields['host'].get()+'? Остановка и перезапуск обрывают текущие подключения.',parent=self):self.run_job({**self.profile(),'action':action})
        self.guarded(operation)

    def http_probe(self):
        def action():
            c=self.need_config();p=self.profile();urls=self.check_urls.get().split()
            if not urls:raise ValueError('Укажите HTTPS URL во вкладке «Обзор»')
            source=resource('remote_agent.py').read_text(encoding='utf-8')+'\nprint(json.dumps(checks('+repr(c)+','+repr(p['service'])+','+repr(urls)+'),ensure_ascii=False))\n'
            self.task('Проверка HTTPS без изменения конфига…',lambda:self.ssh.command('python3 -',source,90),lambda r:self.show_text('Результат HTTPS-проверки',r+'\nУспех короткой проверки не гарантирует длительную стабильность.'))
        self.guarded(action)

    def restore_backup(self):
        def action():
            self.need_config();selected=self.backups.selection()
            if not selected:raise ValueError('Выберите резервную копию')
            ident=selected[0]
            if not all(x in '0123456789TZabcdef-'for x in ident):raise ValueError('Некорректный идентификатор')
            command="python3 -c "+__import__('shlex').quote("from pathlib import Path; print(Path('/var/backups/vless-manager/"+ident+"/config').read_text())")
            self.task('Чтение резервной копии…',lambda:json.loads(self.ssh.command(command)),lambda c:self.review(c,'Восстановление копии '+ident,restore_id=ident))
        self.guarded(action)

    def close_app(self):
        if self.busy and not messagebox.askyesno('Закрыть программу','Операция ещё выполняется. Запущенное задание продолжится на сервере; его статус можно проверить после повторного подключения. Закрыть?',parent=self):return
        if self.ssh:self.ssh.close()
        self.destroy()

def main():
    if '--self-test' in sys.argv:
        report=Path(sys.argv[sys.argv.index('--self-test')+1])
        try:
            app=App();app.withdraw();app.update_idletasks()
            state={'ok':True,'version':APP_VERSION,'tabs':list(app.pages),'readonly_default':app.readonly.get(),'tk':app.tk.call('info','patchlevel'),'paramiko':__import__('paramiko').__version__}
            if IS_MAC:
                backend=credentials.mac_keychain()
                state['credential_backend']=type(backend).__module__+'.'+type(backend).__name__
            report.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8');app.destroy()
        except Exception:
            import traceback
            report.write_text(traceback.format_exc(),encoding='utf-8');raise
    else:
        app=App()
        def callback_error(exc,value,tb):
            import traceback
            messagebox.showerror('VLESS Manager',''.join(traceback.format_exception_only(exc,value)).strip(),parent=app)
        app.report_callback_exception=callback_error;app.mainloop()

if __name__=='__main__':main()
