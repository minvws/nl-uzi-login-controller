# System summary

The login controller is a repository meant to be used alongside [Multiple Authentication eXchange](https://github.com/minvws/nl-rdo-max) (MAX). The purpose of this system 
is to manage sessions for login methods exchanged through MAX for Uzi (Unieke zorgverlener identificatie). The main login methods managed are:

* Yivi (formerly known as IRMA)
* Uzi Pass
* OpenID Connect

The application is built with FastAPI, and consist primarily of two routers:

* Login router: facing MAX managing the login methods requested from MAX.
* Session router: facing external authentication services to fulfill the login flow and return the results

# setup
```bash
make setup
bash scripts/setup-secrets.sh
```
# run
```bash
make run
```

### Update Yivi package
The Yivi packages are included via npm and can be updated in the package.json file. The Yivi packages are used in the `resources/js/app.js` and `resources/css/app.scss` files.

### Docker containers
Docker containers and their configurations are meant to be used for development purposes only. And not meant to be used in a production setup. 
