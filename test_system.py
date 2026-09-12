import unittest
from app import Service, App


class SystemTest(unittest.TestCase):
    def setUp(self):
        self.s=Service(':memory:')
        self.s.bootstrap('admin','Admin123456','管理员')
        self.admin,_=self.s.login('admin','Admin123456','ROLE_ADMIN')
        self.s.add_house(self.admin,'1 栋 101')
        self.s.add_house(self.admin,'2 栋 202')

    def tearDown(self):
        self.s.db.close()

    def user(self,name,roles,house=None):
        self.s.create_user(self.admin,name,'Initial1234',name,roles,house,'物业部')
        token,pending=self.s.login(name,'Initial1234',roles[0])
        self.assertTrue(pending)
        with self.assertRaises(ValueError): self.s.rows(token,'费用账单')
        self.s.change_password(token,'Changed1234')
        self.assertNotIn(token,self.s.sessions)
        return self.s.login(name,'Changed1234',roles[0])[0]

    def test_roles_and_owner_scope(self):
        finance=self.user('finance',['ROLE_FINANCE','ROLE_PROPERTY'])
        with self.assertRaises(ValueError): self.s.add_house(finance,'非法房屋')
        with self.assertRaises(ValueError): self.s.login('finance','Changed1234','ROLE_ADMIN')
        property_token,_=self.s.login('finance','Changed1234','ROLE_PROPERTY')
        self.s.add_house(property_token,'3 栋 303')
        self.s.add_bill(finance,1,'物业费','100.25')
        self.s.add_bill(finance,2,'物业费','200.00')
        owner=self.user('owner',['ROLE_OWNER'],1)
        self.assertEqual(len(self.s.rows(owner,'费用账单')[1]),1)
        with self.assertRaises(ValueError): self.s.pay_bill(owner,1)
        self.s.add_repair(owner,'厨房漏水')
        other=self.user('other',['ROLE_OWNER'],2)
        self.assertEqual(self.s.rows(other,'报修工单')[1],[])
        self.s.complete_repair(property_token,1)
        self.assertEqual(self.s.rows(owner,'报修工单')[1][0][3],'已完成')
        self.s.pay_bill(finance,1)
        self.assertEqual(self.s.rows(owner,'费用账单')[1][0][4],'已缴费')

    def test_lock_reset_and_audit(self):
        owner=self.user('owner',['ROLE_OWNER'],1)
        for _ in range(5):
            with self.assertRaises(ValueError): self.s.login('owner','wrong','ROLE_OWNER')
        with self.assertRaises(ValueError): self.s.rows(owner,'费用账单')
        with self.assertRaises(ValueError): self.s.login('owner','Changed1234','ROLE_OWNER')
        self.s.set_lock(self.admin,2,False)
        token,_=self.s.login('owner','Changed1234','ROLE_OWNER')
        self.s.reset_password(self.admin,2,'Reset123456')
        self.assertNotIn(token,self.s.sessions)
        token,pending=self.s.login('owner','Reset123456','ROLE_OWNER')
        self.assertTrue(pending)
        self.assertGreater(len(self.s.rows(self.admin,'登录审计')[1]),5)

    def test_creation_rollback_and_password_storage(self):
        with self.assertRaises(ValueError):
            self.s.create_user(self.admin,'bad','Initial1234','业主',['ROLE_OWNER'])
        self.assertEqual(self.s.db.execute('SELECT count(*) FROM sys_user').fetchone()[0],1)
        stored=self.s.db.execute('SELECT password_hash FROM sys_user').fetchone()[0]
        self.assertNotIn('Admin123456',stored)
        with self.assertRaises(ValueError): self.s.bootstrap('another','Admin123456','其他')

    def test_gui_routes(self):
        app=App(self.s)
        app.withdraw()
        try:
            for role in ['ROLE_ADMIN','ROLE_PROPERTY','ROLE_FINANCE','ROLE_OWNER']:
                if role=='ROLE_ADMIN': token=self.admin
                else: token=self.user(role,[role],1 if role=='ROLE_OWNER' else None)
                app.token=token
                app.main_view()
                from app import LayoutFactory
                for page in LayoutFactory.create(role):
                    app.page(page)
                    app.update_idletasks()
            app.password_view()
            app.update_idletasks()
        finally: app.destroy()


if __name__=='__main__': unittest.main(verbosity=2)
