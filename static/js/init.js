(function(){
    addEventListener("load", (event) => {
        let data = document.getElementById("info").dataset

        let serverSentEvents = undefined
        if (data.session_server_events_enabled.toLowerCase() === 'true') {
            serverSentEvents = {
              endpoint: 'statusevents',
              timeout:  data.session_server_events_timeout
            }
        }
        else {
            serverSentEvents = false
        }
        let state = {
            serverSentEvents: serverSentEvents,
            polling: {
              endpoint:   'status',
              interval:   data.session_polling_interval,
              startState: 'INITIALIZED'
            }
        }

        let options = {
            // Developer options
            debugging: false,

            // Front-end options
            language:  'en',
            translations: {
                header:  data.title + ' - login',
                loading: 'Just one second please!'
            },
            state: state,

            // Back-end options
            session: {
                start: {
                    url: o => `${o.url}` + '/session/' + data.exchange_token + '/yivi',
                },
                result: false,
                mapping: {
                    sessionPtr: r => r,
                },
            },
        };

        const yiviPopup = yivi.newPopup({
            ...options,
            element: '#yivi-web-form'
        });
        yiviPopup.start().then(() => {
            window.location.assign(data.redirect_url + '?state=' + data.state);
        })
        .catch((err) => {
            if (err === 'Aborted') {
                window.location.assign(data.redirect_url + '?state=' + data.state + '&error=login_required');
            } else {
                let url = new URL(data.redirect_url + '?state=' + data.state + '&error=unknown_exception');
                url.searchParams.append('error_description', err);
                window.location.assign(url);
            }
        });
    });
})();
