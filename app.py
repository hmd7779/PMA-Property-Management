import os
import sqlite3
import hashlib
import hmac
import secrets
import socket
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

ROLES = {'ROLE_ADMIN': '超级管理员', 'ROLE_PROPERTY': '物业主管', 'ROLE_FINANCE': '财务专员', 'ROLE_OWNER': '业主'}
STATUS = {1: '已激活', 2: '已锁定', 3: '待激活'}


def password_hash(password):
    salt = secrets.token_hex(16)
    return salt + ':' + hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 310000).hex()


def password_matches(password, stored):
    salt, digest = stored.split(':')
    return hmac.compare_digest(digest, hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 310000).hex())


def validate_password(password):
    if len(password) < 10 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        raise ValueError('密码至少 10 位，且包含字母和数字')


class Service:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.sessions = {}
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS sys_user (
          user_id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, real_name TEXT NOT NULL,
          status INTEGER NOT NULL DEFAULT 3 CHECK(status IN (1,2,3)),
          is_first_login INTEGER NOT NULL DEFAULT 1,
          create_by INTEGER NOT NULL REFERENCES sys_user(user_id),
          create_time TEXT DEFAULT CURRENT_TIMESTAMP, failed_attempts INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS house (house_id INTEGER PRIMARY KEY, address TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS sys_user_role (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES sys_user(user_id),
          role_code TEXT NOT NULL, bind_house_id INTEGER REFERENCES house(house_id), department TEXT,
          UNIQUE(user_id,role_code), CHECK(role_code IN ('ROLE_ADMIN','ROLE_PROPERTY','ROLE_FINANCE','ROLE_OWNER')),
          CHECK(role_code != 'ROLE_OWNER' OR bind_house_id IS NOT NULL));
        CREATE TABLE IF NOT EXISTS sys_login_log (
          log_id INTEGER PRIMARY KEY, username TEXT, selected_role TEXT, login_ip TEXT,
          result INTEGER, failure_reason TEXT, create_time TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS bill (id INTEGER PRIMARY KEY, house_id INTEGER NOT NULL REFERENCES house(house_id),
          item TEXT NOT NULL, cents INTEGER NOT NULL CHECK(cents>0), status TEXT DEFAULT '待缴费');
        CREATE TABLE IF NOT EXISTS repair (id INTEGER PRIMARY KEY, house_id INTEGER NOT NULL REFERENCES house(house_id),
          description TEXT NOT NULL, status TEXT DEFAULT '待处理', create_time TEXT DEFAULT CURRENT_TIMESTAMP);
        ''')

    def initialized(self):
        return bool(self.db.execute('SELECT 1 FROM sys_user').fetchone())

    def bootstrap(self, username, password, name):
        if self.initialized():
            raise ValueError('系统已初始化')
        validate_password(password)
        if not username.strip() or not name.strip():
            raise ValueError('请填写账号和姓名')
        with self.db:
            self.db.execute('INSERT INTO sys_user(user_id,username,password_hash,real_name,status,is_first_login,create_by) VALUES(1,?,?,?,1,0,1)', (username.strip(), password_hash(password), name.strip()))
            self.db.execute("INSERT INTO sys_user_role(user_id,role_code,department) VALUES(1,'ROLE_ADMIN','系统管理')")

    def log(self, username, role, result, reason=''):
        self.db.execute('INSERT INTO sys_login_log(username,selected_role,login_ip,result,failure_reason) VALUES(?,?,?,?,?)', (username, role, socket.gethostname(), result, reason))
        self.db.commit()

    def login(self, username, password, role):
        user = self.db.execute('SELECT * FROM sys_user WHERE username=?', (username,)).fetchone()
        if user and user['status'] == 2:
            self.log(username, role, 0, '账号已锁定')
            raise ValueError('账号已被锁定，请联系管理员')
        if not user or not password_matches(password, user['password_hash']):
            if user:
                self.db.execute('UPDATE sys_user SET failed_attempts=failed_attempts+1, status=CASE WHEN failed_attempts+1>=5 THEN 2 ELSE status END WHERE user_id=?', (user['user_id'],))
            self.log(username, role, 0, '账号或密码错误')
            raise ValueError('账号或密码错误；连续输错 5 次将锁定')
        self.db.execute('UPDATE sys_user SET failed_attempts=0 WHERE user_id=?', (user['user_id'],))
        if not self.db.execute('SELECT 1 FROM sys_user_role WHERE user_id=? AND role_code=?', (user['user_id'], role)).fetchone():
            self.log(username, role, 0, '角色不匹配')
            raise ValueError('当前账号无此角色权限，请重新选择')
        pending = bool(user['is_first_login'] or user['status'] == 3)
        token = secrets.token_urlsafe(32)
        self.sessions[token] = (user['user_id'], role, pending)
        self.log(username, role, 1, '凭证验证通过，等待首次改密' if pending else '')
        return token, pending

    def context(self, token, allowed=None, allow_pending=False):
        if token not in self.sessions:
            raise ValueError('请重新登录')
        uid, role, pending = self.sessions[token]
        user = self.db.execute('SELECT * FROM sys_user WHERE user_id=?', (uid,)).fetchone()
        binding = self.db.execute('SELECT * FROM sys_user_role WHERE user_id=? AND role_code=?', (uid, role)).fetchone()
        if user['status'] == 2 or not binding:
            raise ValueError('账号已锁定或角色已失效，请联系管理员')
        if (pending or user['is_first_login']) and not allow_pending:
            raise ValueError('请先修改初始密码')
        if allowed and role not in allowed:
            raise ValueError('当前身份无权执行此操作')
        return user, role, binding

    def change_password(self, token, new_password):
        user, _, _ = self.context(token, allow_pending=True)
        validate_password(new_password)
        if password_matches(new_password, user['password_hash']):
            raise ValueError('新密码不能与原密码相同')
        with self.db:
            self.db.execute('UPDATE sys_user SET password_hash=?,status=1,is_first_login=0,failed_attempts=0 WHERE user_id=?', (password_hash(new_password), user['user_id']))
        self.sessions = {k:v for k,v in self.sessions.items() if v[0] != user['user_id']}

    def create_user(self, token, username, password, name, roles, house_id=None, department=''):
        admin, _, _ = self.context(token, ['ROLE_ADMIN'])
        validate_password(password)
        if not username.strip() or not name.strip() or not roles or any(r not in ROLES for r in roles):
            raise ValueError('账号、姓名和有效角色均为必填项')
        if 'ROLE_OWNER' in roles and not house_id:
            raise ValueError('业主必须关联房屋')
        if any(r != 'ROLE_OWNER' for r in roles) and not department.strip():
            raise ValueError('员工角色必须关联部门')
        with self.db:
            uid = self.db.execute('INSERT INTO sys_user(username,password_hash,real_name,create_by) VALUES(?,?,?,?)', (username.strip(), password_hash(password), name.strip(), admin['user_id'])).lastrowid
            for role in roles:
                self.db.execute('INSERT INTO sys_user_role(user_id,role_code,bind_house_id,department) VALUES(?,?,?,?)', (uid, role, house_id if role == 'ROLE_OWNER' else None, department))

    def set_lock(self, token, uid, locked):
        admin, _, _ = self.context(token, ['ROLE_ADMIN'])
        if uid == admin['user_id']:
            raise ValueError('不能锁定或解锁当前账号')
        with self.db:
            self.db.execute('UPDATE sys_user SET status=CASE WHEN ? THEN 2 WHEN is_first_login=1 THEN 3 ELSE 1 END,failed_attempts=0 WHERE user_id=?', (locked, uid))
        self.sessions = {k:v for k,v in self.sessions.items() if v[0] != uid}

    def reset_password(self, token, uid, password):
        admin, _, _ = self.context(token, ['ROLE_ADMIN'])
        if uid == admin['user_id']:
            raise ValueError('请使用右上角修改密码')
        validate_password(password)
        with self.db:
            self.db.execute('UPDATE sys_user SET password_hash=?,status=3,is_first_login=1,failed_attempts=0 WHERE user_id=?', (password_hash(password), uid))
        self.sessions = {k:v for k,v in self.sessions.items() if v[0] != uid}

    def rows(self, token, page):
        user, role, binding = self.context(token)
        if page == '用户管理':
            self.context(token, ['ROLE_ADMIN'])
            return ['ID','登录名','姓名','状态','角色'], [tuple(r)[:3]+(STATUS[r[3]], ', '.join(ROLES[x] for x in r[4].split(','))) for r in self.db.execute('SELECT u.user_id,u.username,u.real_name,u.status,group_concat(r.role_code) FROM sys_user u JOIN sys_user_role r ON r.user_id=u.user_id GROUP BY u.user_id')]
        if page == '登录审计':
            self.context(token, ['ROLE_ADMIN'])
            return ['ID','账号','所选角色','主机','结果','说明','时间 UTC'], [tuple(r) for r in self.db.execute('SELECT * FROM sys_login_log ORDER BY log_id DESC LIMIT 500')]
        if page == '房屋档案':
            self.context(token, ['ROLE_ADMIN','ROLE_PROPERTY'])
            return ['ID','房屋地址'], [tuple(r) for r in self.db.execute('SELECT * FROM house')]
        if page == '费用账单':
            self.context(token, ['ROLE_FINANCE','ROLE_OWNER'])
            sql = 'SELECT b.id,h.address,b.item,b.cents,b.status FROM bill b JOIN house h ON h.house_id=b.house_id'
            rows = self.db.execute(sql + (' WHERE b.house_id=?' if role == 'ROLE_OWNER' else ''), (binding['bind_house_id'],) if role == 'ROLE_OWNER' else ())
            return ['ID','房屋','费用项目','金额（元）','状态'], [(r[0],r[1],r[2],f'{r[3]/100:.2f}',r[4]) for r in rows]
        if page == '报修工单':
            self.context(token, ['ROLE_PROPERTY','ROLE_OWNER'])
            sql = 'SELECT r.id,h.address,r.description,r.status,r.create_time FROM repair r JOIN house h ON h.house_id=r.house_id'
            return ['ID','房屋','报修描述','状态','时间 UTC'], [tuple(r) for r in self.db.execute(sql + (' WHERE r.house_id=?' if role == 'ROLE_OWNER' else ''), (binding['bind_house_id'],) if role == 'ROLE_OWNER' else ())]
        raise ValueError('未知页面')

    def add_house(self, token, address):
        self.context(token, ['ROLE_ADMIN','ROLE_PROPERTY'])
        if not address.strip(): raise ValueError('请输入房屋地址')
        with self.db: self.db.execute('INSERT INTO house(address) VALUES(?)', (address.strip(),))

    def houses(self, token):
        self.context(token, ['ROLE_ADMIN','ROLE_PROPERTY','ROLE_FINANCE'])
        return list(self.db.execute('SELECT * FROM house'))

    def add_bill(self, token, house_id, item, amount):
        from decimal import Decimal
        self.context(token, ['ROLE_FINANCE'])
        value = Decimal(amount)
        if not value.is_finite() or value <= 0 or value > 100000000 or value != value.quantize(Decimal('0.01')) or not item.strip():
            raise ValueError('请填写费用项目及有效金额（最多两位小数）')
        with self.db: self.db.execute('INSERT INTO bill(house_id,item,cents) VALUES(?,?,?)', (house_id,item.strip(),int(value*100)))

    def pay_bill(self, token, bid):
        self.context(token, ['ROLE_FINANCE'])
        with self.db: self.db.execute("UPDATE bill SET status='已缴费' WHERE id=?", (bid,))

    def add_repair(self, token, description):
        _, _, binding = self.context(token, ['ROLE_OWNER'])
        if not description.strip(): raise ValueError('请填写报修描述')
        with self.db: self.db.execute('INSERT INTO repair(house_id,description) VALUES(?,?)', (binding['bind_house_id'], description.strip()))

    def complete_repair(self, token, rid):
        self.context(token, ['ROLE_PROPERTY'])
        with self.db: self.db.execute("UPDATE repair SET status='已完成' WHERE id=?", (rid,))


class LayoutFactory:
    menus = {'ROLE_ADMIN':['用户管理','房屋档案','登录审计'], 'ROLE_PROPERTY':['报修工单','房屋档案'], 'ROLE_FINANCE':['费用账单'], 'ROLE_OWNER':['费用账单','报修工单']}
    @classmethod
    def create(cls, role):
        return cls.menus[role].copy()


class App(tk.Tk):
    def __init__(self, service):
        super().__init__()
        self.s = service
        self.token = None
        self.title('邻里云 · 物业管理系统')
        self.geometry('1180x760')
        self.minsize(960,650)
        self.configure(bg='#f3f6fa')
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', font=('Microsoft YaHei UI',11))
        style.configure('TFrame', background='#f3f6fa')
        style.configure('TLabel', background='#f3f6fa', foreground='#172b4d')
        style.configure('TButton', padding=(15,9))
        style.configure('Treeview', rowheight=36, background='white', fieldbackground='white')
        style.configure('Treeview.Heading', font=('Microsoft YaHei UI',11,'bold'), padding=10)
        self.login_view()

    def safe(self, fn):
        try: return fn()
        except (ValueError,sqlite3.Error,ArithmeticError) as error:
            messagebox.showerror('操作未完成', '登录名或房屋已存在，或关联数据无效' if isinstance(error,sqlite3.IntegrityError) else str(error), parent=self)

    def clear(self):
        for widget in self.winfo_children(): widget.destroy()

    def fields(self, parent, labels):
        result = {}
        for label in labels:
            ttk.Label(parent,text=label).pack(anchor='w',pady=(12,4))
            value=tk.StringVar()
            ttk.Entry(parent,textvariable=value,show='●' if '密码' in label else '',width=40).pack(fill='x')
            result[label]=value
        return result

    def login_view(self):
        self.clear()
        self.token=None
        box=ttk.Frame(self,padding=40)
        box.place(relx=.5,rely=.5,anchor='center',width=480)
        ttk.Label(box,text='邻里云  /  PMA',font=('Microsoft YaHei UI',26,'bold')).pack(anchor='w')
        init=not self.s.initialized()
        ttk.Label(box,text='首次部署 · 设置系统管理员' if init else '物业服务，从有序协作开始').pack(anchor='w',pady=(8,15))
        values=self.fields(box,['登录名','密码','真实姓名'] if init else ['登录名','密码'])
        if not init:
            ttk.Label(box,text='登录身份 · 请手动选择').pack(anchor='w',pady=(15,4))
            selected=tk.StringVar()
            ttk.Combobox(box,textvariable=selected,values=list(ROLES.values()),state='readonly').pack(fill='x')
        def submit():
            if init:
                self.s.bootstrap(values['登录名'].get(),values['密码'].get(),values['真实姓名'].get())
                self.login_view()
                messagebox.showinfo('初始化完成','请使用刚设置的超级管理员账号登录')
            else:
                if selected.get() not in ROLES.values(): raise ValueError('请手动选择登录身份')
                role=next(k for k,v in ROLES.items() if v==selected.get())
                self.token,pending=self.s.login(values['登录名'].get().strip(),values['密码'].get(),role)
                if pending: self.password_view()
                else: self.main_view()
        ttk.Button(box,text='完成初始化' if init else '登录工作台',command=lambda:self.safe(submit)).pack(fill='x',pady=(25,15))
        ttk.Label(box,text='密码至少 10 位，包含字母和数字' if init else '账号由超级管理员统一分配 · 无公开注册',font=('Microsoft YaHei UI',10)).pack()

    def password_view(self):
        self.clear()
        box=ttk.Frame(self,padding=40)
        box.place(relx=.5,rely=.5,anchor='center')
        ttk.Label(box,text='设置新密码',font=('Microsoft YaHei UI',24,'bold')).pack(anchor='w')
        ttk.Label(box,text='修改完成后重新登录；首次改密前不能访问业务').pack(pady=12)
        fields=self.fields(box,['新密码','确认密码'])
        def submit():
            if fields['新密码'].get()!=fields['确认密码'].get(): raise ValueError('两次密码不一致')
            self.s.change_password(self.token,fields['新密码'].get())
            self.login_view()
            messagebox.showinfo('密码已更新','请使用新密码重新登录')
        ttk.Button(box,text='保存新密码',command=lambda:self.safe(submit)).pack(fill='x',pady=20)
        ttk.Button(box,text='退出登录',command=self.logout).pack(fill='x')

    def logout(self):
        self.s.sessions.pop(self.token,None)
        self.login_view()

    def main_view(self):
        user,self.role,_=self.s.context(self.token)
        self.clear()
        header=ttk.Frame(self,padding=20)
        header.pack(fill='x')
        ttk.Label(header,text='邻里云 · 物业管理',font=('Microsoft YaHei UI',20,'bold')).pack(side='left')
        ttk.Button(header,text='退出登录',command=self.logout).pack(side='right')
        ttk.Button(header,text='修改密码',command=self.password_view).pack(side='right',padx=10)
        ttk.Label(header,text=f"{user['real_name']}  /  {ROLES[self.role]}").pack(side='right',padx=20)
        side=ttk.Frame(self,padding=20,width=220)
        side.pack(side='left',fill='y')
        ttk.Label(side,text='工作空间',font=('Microsoft YaHei UI',10)).pack(anchor='w',pady=10)
        for page in ['工作台']+LayoutFactory.create(self.role):
            ttk.Button(side,text=page,command=lambda p=page:self.safe(lambda:self.page(p))).pack(fill='x',pady=6)
        self.body=ttk.Frame(self,padding=25)
        self.body.pack(side='left',expand=True,fill='both')
        self.page('工作台')

    def dialog(self,title,labels,callback,house=False,roles=False):
        win=tk.Toplevel(self)
        win.title(title)
        win.transient(self)
        win.grab_set()
        body=ttk.Frame(win,padding=25)
        body.pack(fill='both',expand=True)
        fields=self.fields(body,labels)
        houses={}
        hv=tk.StringVar()
        if house:
            houses={f'{r[0]} · {r[1]}':r[0] for r in self.s.houses(self.token)}
            ttk.Label(body,text='关联房屋（业主必填）' if roles else '关联房屋').pack(anchor='w',pady=(12,4))
            ttk.Combobox(body,textvariable=hv,values=list(houses),state='readonly').pack(fill='x')
        rv={}
        if roles:
            ttk.Label(body,text='绑定角色（可多选）').pack(anchor='w',pady=(12,4))
            for code,name in ROLES.items():
                rv[code]=tk.BooleanVar()
                ttk.Checkbutton(body,text=name,variable=rv[code]).pack(anchor='w')
        def save():
            callback({k:v.get() for k,v in fields.items()},houses.get(hv.get()),[k for k,v in rv.items() if v.get()])
            win.destroy()
            self.page(self.current_page)
        ttk.Button(body,text='保存',command=lambda:self.safe(save)).pack(fill='x',pady=(20,0))

    def page(self,page):
        self.s.context(self.token)
        self.current_page=page
        for w in self.body.winfo_children(): w.destroy()
        ttk.Label(self.body,text=page,font=('Microsoft YaHei UI',24,'bold')).pack(anchor='w',pady=(0,10))
        if page=='工作台':
            descriptions={'ROLE_ADMIN':'统一供给账号，管理身份与访问安全。','ROLE_PROPERTY':'跟进居民报修，维护社区房屋档案。','ROLE_FINANCE':'建立费用账单，登记线下收款。','ROLE_OWNER':'查看自家账单，提交房屋报修。'}
            ttk.Label(self.body,text=descriptions[self.role]).pack(anchor='w',pady=10)
            for name in LayoutFactory.create(self.role):
                _,rows=self.s.rows(self.token,name)
                card=ttk.Frame(self.body,padding=20)
                card.pack(fill='x',pady=8)
                ttk.Label(card,text=f'{name}    {len(rows)} 条'+('（最近记录）' if name=='登录审计' else ''),font=('Microsoft YaHei UI',16)).pack(side='left')
                ttk.Button(card,text='进入 →',command=lambda p=name:self.safe(lambda:self.page(p))).pack(side='right')
            return
        columns,rows=self.s.rows(self.token,page)
        bar=ttk.Frame(self.body)
        bar.pack(fill='x',pady=15)
        def button(label,action): ttk.Button(bar,text=label,command=lambda:self.safe(action)).pack(side='left',padx=(0,8))
        button('刷新',lambda:self.page(page))
        if page=='用户管理':
            button('创建账号',lambda:self.dialog('创建账号',['登录名','初始密码','真实姓名','部门'],lambda v,h,r:self.s.create_user(self.token,v['登录名'],v['初始密码'],v['真实姓名'],r,h,v['部门']),house=True,roles=True))
            button('锁定',lambda:self.user_lock(True))
            button('解锁',lambda:self.user_lock(False))
            button('重置密码',self.reset_user)
        elif page=='房屋档案':
            button('新增房屋',lambda:self.dialog('新增房屋',['房屋地址'],lambda v,h,r:self.s.add_house(self.token,v['房屋地址'])))
        elif page=='费用账单' and self.role=='ROLE_FINANCE':
            button('新增账单',lambda:self.dialog('新增账单',['费用项目','金额'],lambda v,h,r:self.s.add_bill(self.token,h,v['费用项目'],v['金额']),house=True))
            button('登记已缴费',self.pay)
        elif page=='报修工单':
            if self.role=='ROLE_OWNER': button('提交报修',lambda:self.dialog('提交报修',['报修描述'],lambda v,h,r:self.s.add_repair(self.token,v['报修描述'])))
            else: button('标记已完成',self.complete)
        frame=ttk.Frame(self.body)
        frame.pack(fill='both',expand=True)
        self.tree=ttk.Treeview(frame,columns=columns,show='headings',selectmode='browse')
        for col in columns:
            self.tree.heading(col,text=col)
            self.tree.column(col,width=150 if col!='ID' else 55,minwidth=55)
        y=ttk.Scrollbar(frame,orient='vertical',command=self.tree.yview)
        x=ttk.Scrollbar(frame,orient='horizontal',command=self.tree.xview)
        self.tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)
        frame.columnconfigure(0,weight=1)
        frame.rowconfigure(0,weight=1)
        self.tree.grid(row=0,column=0,sticky='nsew')
        y.grid(row=0,column=1,sticky='ns')
        x.grid(row=1,column=0,sticky='ew')
        for row in rows: self.tree.insert('', 'end',values=row)
        ttk.Label(self.body,text=f'共 {len(rows)} 条记录'+(' · 仅显示所关联房屋的数据' if self.role=='ROLE_OWNER' else '')).pack(anchor='w',pady=12)

    def selected(self):
        selection=self.tree.selection()
        if not selection: raise ValueError('请先选择一条记录')
        return int(self.tree.item(selection[0],'values')[0])

    def user_lock(self,locked):
        self.s.set_lock(self.token,self.selected(),locked)
        self.page(self.current_page)

    def reset_user(self):
        uid=self.selected()
        password=simpledialog.askstring('重置密码','请输入新初始密码（至少 10 位，含字母和数字）',show='●',parent=self)
        if password is not None:
            self.s.reset_password(self.token,uid,password)
            self.page(self.current_page)

    def pay(self):
        uid=self.selected()
        if messagebox.askyesno('确认收款','确认已在线下收到该账单款项？',parent=self):
            self.s.pay_bill(self.token,uid)
            self.page(self.current_page)

    def complete(self):
        self.s.complete_repair(self.token,self.selected())
        self.page(self.current_page)


if __name__=='__main__':
    data=Path(__file__).resolve().parent / 'data'
    data.mkdir(parents=True,exist_ok=True)
    service=Service(data/'pma.sqlite3')
    App(service).mainloop()
