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
