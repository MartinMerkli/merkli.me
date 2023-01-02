# merkli.me

This is the source code of [merkli.me](https://merkli.me/).
You can report bugs [here](https://github.com/Emil105105/merkli.me/issues).

## Copyright

Even though you can view and download the source code, this project is not 'open source'.

See LICENSE.txt for more information.

## Hosting the website locally

Please note that it will not work on any operating system other than any Debian-based distros. 

### Dependencies

You need to install the following prerequisites:

- nginx
- python3.10
- pip
- python-venv
- supervisorctl

They can be installed using the following command:
```
sudo apt-get update
sudo apt-get install nginx python3 python3-pip python3-venv supervisor
```

All python-libraries listed in `requirements.txt` have to be installed as well. Use the following command for this 
while being in the root:
```
mkdir -p venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Create database

The installer (`python3 installer.py`) will do this automatically.

### Configuration

#### gunicorn

You have to specify some settings in `gunicorn.conf.py`. The required parameters are explained in the file.

#### Nginx

The file `/config/flaskserver` has to be moved to `/etc/nginx/sites-enabled/`. You probably have to change the server
name as well as the port number and remove the SSL-certificate. Use `sudo systemctl restart nginx` to restart nginx. 
Copy `/config/502.html` to `/var/www/html/`. 

#### Supervisorctl

All files ending with `.conf` have to be copied to `/etc/supervisor/conf.d`. Supervisorctl then has to be restarted with
```
sudo supervisorctl reread
sudo supervisorctl update
```

### Firewall

You may have to allow certain ports in your firewall settings. Due to the huge variety in available firewalls is it not
possible to create an instruction which covers all of them.

### Check availability

With `sudo supvervisorctl status` you can check the status of the three processes (flaskserver, flaskserver_mensa and
flaskserver_backup).
