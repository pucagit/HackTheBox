# Web Mass Assignment Vulnerabilities
Ruby on Rails is a web application framework that is vulnerable to this type of attack. Assuming we have a `User` model with the following attributes:

```
class User < ActiveRecord::Base
  attr_accessible :username, :email
end
```

However, attackers can modify other attributes by tampering with the parameters sent to the server. Let's assume that the server receives the following parameters.

```
{ "user" => { "username" => "hacker", "email" => "hacker@example.com", "admin" => true } }
```

Although the `User` model does not explicitly state that the `admin` attribute is accessible, the attacker can still change it because it is present in the arguments.

## Questions
SSH to 10.129.205.15 (ACADEMY-ACA-CLAMP), with user `root` and password `!x4;EW[ZLwmDx?=w`
1. We placed the source code of the application we just covered at /opt/asset-manager/app.py inside this exercise's target, but we changed the crucial parameter's name. SSH into the target, view the source code and enter the parameter name that needs to be manipulated to log in to the Asset Manager web application. **Answer: active**
   - SSH into the target and read the source code, the parameter that sets `cond=True` is `active`:
        ```python
        @app.route('/register',methods=['GET','POST'])
        def register():
            if request.method=='GET':
                return render_template('index.html')
            else:
                username=request.form['username']
                password=request.form['password']
                try:
                    if request.form['active']:
                        cond=True
                except:
                        cond=False
                with sqlite3.connect("database.db") as con:
                    cur = con.cursor()
                    cur.execute('select * from users where username=?',(username,))
                    if cur.fetchone():
                        return render_template('index.html',value='User exists!!')
                    else:
                        cur.execute('insert into users values(?,?,?)',(username,password,cond))
                        con.commit()
                        return render_template('index.html',value='Success!!')
        ```