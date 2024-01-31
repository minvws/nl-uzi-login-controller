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
The Yivi JavaScript package is included as a single static yivi.js file and an init.js that takes care of settings. To
update the Yivi version, clone the [yivi-frontend-packages/](https://github.com/privacybydesign/yivi-frontend-packages/)
repository. Inside it, run `npm install` followed by `npm run build`. Then replace the `static/yivi.js` with the 
`yivi-frontend-packages/yivi-frontend/dist/yivi.js` file.
